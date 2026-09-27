package com.asmolabs.vectispire.core.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus.State;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFeed;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFileSource;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * FIRST's EPSS file, the size FIRST publishes it, written on a real engine.
 *
 * <p><b>Why this is in the campaign.</b> The write is hand-built SQL — {@code insert … values} of
 * five hundred rows, two thousand bind parameters — and the clean-up a keyset range over a
 * composite key, read with an offset: the statement's size, the parameter ceiling and the ordering
 * of {@code cve_id} under the column's collation are each the engine's. And the time it takes is the
 * engine's too: the KEV catalogue's first synchronisation, a few thousand rows by {@code merge}, was
 * slow, and this is a hundred times more rows. Each phase's time is printed with the engine's name
 * ({@code EPSS-BENCH}), so the report of a run says what it measured.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the EPSS file, stored on a real engine")
class EpssScoresIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    /** FIRST's file on 27 September 2026: 380,066 rows. */
    private static final int ROWS = 380_066;
    private static final int OPEN_ISSUES = 2_000;
    private static final Instant DAY = Instant.parse("2026-09-27T12:00:21Z");

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private EpssFeed feed;

    @Autowired
    private EpssScoreRepository scores;

    @Autowired
    private ThreatIntelSyncRepository syncs;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private JdbcTemplate jdbc;

    @MockitoBean
    private EpssFileSource source;

    @BeforeEach
    void empty() {
        jdbc.execute("delete from t_epss_score");
        jdbc.execute("delete from t_issue");
        jdbc.execute("delete from t_threat_intel_sync");
        // The row V43 leaves on every installation. Not left for the feed to create: four instances
        // creating it at once is a race no deployment runs, and on SQLite it is a lock upgrade that
        // fails instead of waiting.
        syncs.save(new ThreatIntelSyncEntity());
        when(source.location()).thenReturn("https://epss.example.invalid/");
    }

    @Test
    @DisplayName("a whole file is written, applied and read back; a newer one replaces it and the old one is deleted")
    void writesAndReplacesAWholeFile() {
        List<IssueEntity> open = openIssues();
        when(source.fetch()).thenReturn(file(ROWS, DAY.minusSeconds(86_400), 0));

        long started = System.nanoTime();
        EpssFeed.Attempt first = feed.sync();
        long firstMillis = elapsed(started);

        assertThat(first.outcome()).as(String.valueOf(first.reason())).isEqualTo(EpssFeed.Outcome.APPLIED);
        assertThat(first.status().totalScored()).isEqualTo(ROWS);
        assertThat(first.status().backlogUpdatedCount()).isEqualTo(OPEN_ISSUES);
        assertThat(scores.count()).isEqualTo(ROWS);
        assertThat(feed.scoresOf(List.of(cve(123_456))).get(cve(123_456)).score()).isEqualTo(score(123_456, 0));
        assertThat(issues.findById(open.get(10).getId()).orElseThrow().getEpssScore())
                .isEqualTo(score(row(10), 0));

        when(source.fetch()).thenReturn(file(ROWS + 7, DAY, 11));
        started = System.nanoTime();
        EpssFeed.Attempt second = feed.sync();
        long secondMillis = elapsed(started);

        assertThat(second.outcome()).as(String.valueOf(second.reason())).isEqualTo(EpssFeed.Outcome.APPLIED);
        assertThat(scores.count()).as("the replaced generation is deleted, whole").isEqualTo(ROWS + 7);
        long current = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID).orElseThrow().getEpssGeneration();
        assertThat(scores.generationsOtherThan(current)).isEmpty();
        assertThat(issues.findById(open.get(10).getId()).orElseThrow().getEpssScore())
                .isEqualTo(score(row(10), 11));

        started = System.nanoTime();
        EpssFeed.Attempt again = feed.sync();
        long confirmMillis = elapsed(started);
        assertThat(again.outcome()).isEqualTo(EpssFeed.Outcome.UNCHANGED);

        System.out.printf(Locale.ROOT,
                "EPSS-BENCH engine=%s rows=%d first=%d ms replace=%d ms same-file=%d ms (open issues re-scored: %d)%n",
                ENGINE.name().toLowerCase(Locale.ROOT), ROWS, firstMillis, secondMillis, confirmMillis, OPEN_ISSUES);
    }

    @Test
    @DisplayName("a file refused half-way leaves the scores in use, and nothing of itself")
    void aRefusedFileLeavesNothing() {
        when(source.fetch()).thenReturn(file(120_000, DAY.minusSeconds(86_400), 0));
        assertThat(feed.sync().outcome()).isEqualTo(EpssFeed.Outcome.APPLIED);

        byte[] whole = file(ROWS, DAY, 3);
        when(source.fetch()).thenReturn(java.util.Arrays.copyOf(whole, whole.length * 3 / 4));
        EpssFeed.Attempt refused = feed.sync();

        assertThat(refused.outcome()).isEqualTo(EpssFeed.Outcome.FAILED);
        assertThat(refused.status().status()).isEqualTo(State.FAILED);
        assertThat(scores.count()).isEqualTo(120_000);
        assertThat(feed.scoresOf(List.of(cve(7))).get(cve(7)).score()).isEqualTo(score(7, 0));
    }

    @Test
    @DisplayName("instances asking at the same instant elect one")
    void oneInstanceIsElected() throws Exception {
        when(source.fetch()).thenReturn(file(120_000, DAY, 0));
        int instances = 4;
        CyclicBarrier together = new CyclicBarrier(instances);
        ExecutorService pool = Executors.newFixedThreadPool(instances);
        try {
            List<Future<Optional<EpssFeed.Attempt>>> turns = new ArrayList<>();
            for (int instance = 0; instance < instances; instance++) {
                turns.add(pool.submit(() -> {
                    together.await(30, TimeUnit.SECONDS);
                    return feed.syncIfDue();
                }));
            }
            int ran = 0;
            for (Future<Optional<EpssFeed.Attempt>> turn : turns) {
                ran += turn.get(120, TimeUnit.SECONDS).isPresent() ? 1 : 0;
            }
            assertThat(ran).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
        verify(source, times(1)).fetch();
        assertThat(scores.count()).isEqualTo(120_000);
    }

    /** Open issues on CVE spread over the whole file, scored nothing yet. */
    private List<IssueEntity> openIssues() {
        List<IssueEntity> created = new ArrayList<>();
        for (int index = 0; index < OPEN_ISSUES; index++) {
            IssueEntity issue = new IssueEntity();
            issue.setType("vulnerability");
            issue.setIdentifier(cve(row(index)));
            issue.setFingerprint("fp-epss-" + index + "-" + System.nanoTime());
            issue.setPackageName("openssl");
            issue.setSource("grype");
            issue.setSeverity("high");
            issue.setState("open");
            issue.setFirstSeenAt(Instant.now());
            issue.setLastSeenAt(Instant.now());
            issue.setTriageStatus("untriaged");
            created.add(issue);
        }
        return issues.saveAll(created);
    }

    private static int row(int issue) {
        return issue * 190;
    }

    private static long elapsed(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }

    private static String cve(int row) {
        return String.format(Locale.ROOT, "CVE-2020-%04d", row);
    }

    private static double score(int row, int shift) {
        return Double.parseDouble(String.format(Locale.ROOT, "%.6f", (row + shift) / 1_000_000.0 % 1.0));
    }

    /** As FIRST publishes it; the integration sources do not see the unit suite's fixture. */
    private static byte[] file(int rows, Instant date, int shift) {
        StringBuilder text = new StringBuilder(rows * 32);
        text.append("#model_version:v2025.03.14,score_date:").append(date).append('\n');
        text.append("cve,epss,percentile\n");
        for (int row = 0; row < rows; row++) {
            String score = String.format(Locale.ROOT, "%.6f", score(row, shift));
            text.append(cve(row)).append(',').append(score).append(',').append(score).append('\n');
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(text.toString().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }
}
