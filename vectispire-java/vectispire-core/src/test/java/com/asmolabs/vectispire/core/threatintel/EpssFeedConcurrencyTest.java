package com.asmolabs.vectispire.core.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFeed;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFileSource;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.KnownEpssScore;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Two EPSS synchronisations at once, with the interleaving forced rather than hoped for: the first
 * is held inside its download by a latch while the second is asked for.
 *
 * <p>The feed is written over many short transactions, so no row lock serialises two writers the way
 * the KEV catalogue's single transaction does; the lease is what does. These are the two
 * interleavings it exists for: a second request while the first holds it, and a first one so slow
 * that its lease ran out and another took over. And one between a reader and a synchronisation: the
 * reader held between reading the row and reading the scores of the generation it named.
 */
@DisplayName("two EPSS synchronisations at once")
class EpssFeedConcurrencyTest extends VectispireContextTest {

    private static final int ROWS = 100_010;
    private static final Instant START = Instant.parse("2026-09-27T13:00:00Z");

    @Autowired
    private EpssScoreRepository scores;

    @Autowired
    private ThreatIntelSyncRepository syncs;

    @Autowired
    private IssueCatalog issues;

    private final MovableClock clock = new MovableClock(START);
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private EpssFileSource source;
    private EpssFeed feed;

    @BeforeEach
    void wire() {
        source = mock(EpssFileSource.class);
        when(source.location()).thenReturn("https://epss.example.invalid/");
        feed = new EpssFeed(scores, syncs, issues, source, clock);
    }

    @AfterEach
    void stop() {
        executor.shutdownNow();
    }

    @Test
    @DisplayName("a request made while one synchronisation holds the lease is not run a second time")
    void aSecondRequestWaitsItsTurn() throws Exception {
        CountDownLatch downloading = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        byte[] file = EpssFiles.gzip(ROWS, "v2025.03.14", START, 0);
        when(source.fetch()).thenAnswer(call -> {
            downloading.countDown();
            assertThat(release.await(30, TimeUnit.SECONDS)).isTrue();
            return file;
        });

        Future<EpssFeed.Attempt> first = executor.submit(feed::sync);
        assertThat(downloading.await(30, TimeUnit.SECONDS)).isTrue();

        EpssFeed.Attempt second = feed.sync();
        assertThat(second.outcome()).isEqualTo(EpssFeed.Outcome.BUSY);
        assertThat(second.status().inProgress()).isTrue();
        // Nor the schedule: the lease stops it whatever the file's age.
        assertThat(feed.syncIfDue()).isEmpty();

        release.countDown();
        assertThat(first.get(60, TimeUnit.SECONDS).outcome()).isEqualTo(EpssFeed.Outcome.APPLIED);
        verify(source, times(1)).fetch();
        assertThat(feed.status().inProgress()).isFalse();
        assertThat(scores.count()).isEqualTo(ROWS);
    }

    @Test
    @DisplayName("a synchronisation whose lease ran out cannot apply its file, and leaves no row behind")
    void anExpiredLeaseCannotApply() throws Exception {
        CountDownLatch downloading = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        byte[] slow = EpssFiles.gzip(ROWS, "v2025.03.14", START, 700);
        byte[] fast = EpssFiles.gzip(ROWS + 1, "v2025.03.14", START.plusSeconds(3600), 0);
        AtomicInteger fetches = new AtomicInteger();
        when(source.fetch()).thenAnswer(call -> {
            if (fetches.incrementAndGet() == 1) {
                downloading.countDown();
                assertThat(release.await(30, TimeUnit.SECONDS)).isTrue();
                return slow;
            }
            return fast;
        });

        Future<EpssFeed.Attempt> stale = executor.submit(feed::sync);
        assertThat(downloading.await(30, TimeUnit.SECONDS)).isTrue();

        // The first one's lease runs out while it is still downloading, and another takes over.
        clock.advance(Duration.ofMinutes(31));
        EpssFeed.Attempt takeover = feed.sync();
        assertThat(takeover.outcome()).isEqualTo(EpssFeed.Outcome.APPLIED);

        // The stale one wakes up and writes its whole file under its own generation — then finds its
        // claim gone, and neither applies the file nor records its failure over the other's success.
        release.countDown();
        EpssFeed.Attempt late = stale.get(60, TimeUnit.SECONDS);
        assertThat(late.outcome()).isEqualTo(EpssFeed.Outcome.FAILED);
        assertThat(late.reason()).contains("claim on the EPSS feed ran out");

        assertThat(feed.status().status()).isEqualTo(State.SYNCED);
        assertThat(feed.status().totalScored()).isEqualTo(ROWS + 1);
        assertThat(feed.status().lastError()).isNull();
        assertThat(scores.count()).as("the stale generation was discarded").isEqualTo(ROWS + 1);
        assertThat(feed.scoresOf(java.util.List.of(EpssFiles.cve(7))).get(EpssFiles.cve(7)).score())
                .isEqualTo(EpssFiles.score(7, 0));
    }

    @Test
    @DisplayName("a reader that read the generation just before a switch still finds its scores")
    void aReaderOfTheReplacedGenerationFindsItsRows() throws Exception {
        when(source.fetch()).thenReturn(EpssFiles.gzip(ROWS, "v2025.03.14", START, 0));
        assertThat(feed.sync().outcome()).isEqualTo(EpssFeed.Outcome.APPLIED);

        // The reader's two statements with the switch forced between them: the row read, then held
        // until the next file is applied, then the scores of the generation the row named.
        CountDownLatch rowRead = new CountDownLatch(1);
        CountDownLatch switched = new CountDownLatch(1);
        ThreatIntelSyncRepository pausing = mock(ThreatIntelSyncRepository.class, delegatesTo(syncs));
        doAnswer(call -> {
                    Optional<ThreatIntelSyncEntity> row = syncs.findById(call.getArgument(0));
                    rowRead.countDown();
                    assertThat(switched.await(30, TimeUnit.SECONDS)).isTrue();
                    return row;
                })
                .when(pausing)
                .findById(any());
        EpssFeed reader = new EpssFeed(scores, pausing, issues, source, clock);
        Future<Map<String, KnownEpssScore>> read = executor.submit(() -> reader.scoresOf(List.of(EpssFiles.cve(7))));
        assertThat(rowRead.await(30, TimeUnit.SECONDS)).isTrue();

        when(source.fetch()).thenReturn(EpssFiles.gzip(ROWS, "v2025.03.14", START.plusSeconds(86_400), 5));
        assertThat(feed.sync().outcome()).isEqualTo(EpssFeed.Outcome.APPLIED);
        switched.countDown();

        assertThat(read.get(30, TimeUnit.SECONDS))
                .as("the generation the reader read was deleted under it")
                .containsKey(EpssFiles.cve(7));
        assertThat(read.get().get(EpssFiles.cve(7)).score()).isEqualTo(EpssFiles.score(7, 0));
        assertThat(feed.scoresOf(List.of(EpssFiles.cve(7))).get(EpssFiles.cve(7)).score())
                .isEqualTo(EpssFiles.score(7, 5));

        // Kept one file longer, not for ever: the third file deletes the first.
        ThreatIntelSyncEntity second = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID).orElseThrow();
        when(source.fetch()).thenReturn(EpssFiles.gzip(ROWS, "v2025.03.14", START.plusSeconds(2 * 86_400), 9));
        assertThat(feed.sync().outcome()).isEqualTo(EpssFeed.Outcome.APPLIED);
        ThreatIntelSyncEntity third = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID).orElseThrow();
        assertThat(third.getEpssPreviousGeneration()).isEqualTo(second.getEpssGeneration());
        assertThat(scores.generationsOtherThan(List.of(third.getEpssGeneration(), third.getEpssPreviousGeneration())))
                .isEmpty();
        assertThat(scores.count()).isEqualTo(2L * ROWS);
    }

    /** A clock the test moves. */
    private static final class MovableClock extends Clock {

        private final AtomicReference<Instant> now;

        MovableClock(Instant start) {
            now = new AtomicReference<>(start);
        }

        void advance(Duration by) {
            now.updateAndGet(instant -> instant.plus(by));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }
}
