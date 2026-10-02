package com.asmolabs.vectispire.core.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFileSource;
import com.asmolabs.vectispire.core.threatintel.internal.KevCatalogSource;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * CISA's KEV catalogue, the size CISA publishes it, stored and applied on a real engine.
 *
 * <p><b>Why this is in the campaign.</b> The first write of the catalogue is hand-built SQL — rows
 * many to a statement, like the EPSS file's — and the backlog is walked a page at a time, each page
 * under the sync row's write lock: the statement's size and the lock's semantics are each the
 * engine's. And the time the first write takes is the engine's too: through per-row {@code merge} it
 * was one {@code select} and one {@code insert} per CVE. Each phase's time is printed with the
 * engine's name ({@code KEV-BENCH}), so the report of a run says what it measured.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the KEV catalogue, stored on a real engine")
class KevCatalogueIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    /** CISA's catalogue in September 2026 lists some 1,500 CVE. */
    private static final int LISTED = 1_500;

    /** Three pages of the re-evaluation, the last one short. */
    private static final int OPEN_ISSUES = 1_234;

    /** The open issues on an even row: listed, and not flagged yet. */
    private static final int PROMOTED = (OPEN_ISSUES + 1) / 2;

    private static final Instant RELEASED = Instant.parse("2026-09-26T15:00:00Z");

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private ThreatIntelFeedService feed;

    @Autowired
    private ThreatIntelRepository intel;

    @Autowired
    private ThreatIntelSyncRepository syncs;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private JdbcTemplate jdbc;

    @MockitoBean
    private KevCatalogSource source;

    /** Stood in for so that no synchronisation here reaches FIRST; every EPSS attempt fails. */
    @MockitoBean
    private EpssFileSource epssSource;

    @MockitoSpyBean
    private SiemEvents siem;

    @MockitoSpyBean
    private IssueCatalog catalog;

    @BeforeEach
    void empty() {
        jdbc.execute("delete from t_threat_intel_feed");
        jdbc.execute("delete from t_issue");
        jdbc.execute("delete from t_threat_intel_sync");
        syncs.save(new ThreatIntelSyncEntity());
        when(source.location()).thenReturn("https://kev.example.invalid/");
        when(epssSource.location()).thenReturn("https://epss.example.invalid/");
        when(epssSource.fetch()).thenThrow(new IllegalStateException("EPSS: not in this test"));
    }

    @Test
    @DisplayName("the whole catalogue is written on the first synchronisation, and the same one again writes nothing")
    void firstWriteOfTheWholeCatalogue() {
        when(source.fetch()).thenReturn(catalogue(LISTED, RELEASED));

        long started = System.nanoTime();
        ThreatIntelSyncStatus first = synchronise();
        long firstMillis = elapsed(started);

        assertThat(first.status()).as(first.lastError()).isEqualTo(ThreatIntelSyncStatus.State.SYNCED);
        assertThat(first.totalKev()).isEqualTo(LISTED);
        assertThat(intel.count()).isEqualTo(LISTED);
        assertThat(intel.findByCveIdIgnoreCase(cve(1_234 * 2))).get().satisfies(entry -> {
            assertThat(entry.isKev()).isTrue();
            assertThat(entry.getDateAdded()).isEqualTo(added(1_234 * 2));
        });

        started = System.nanoTime();
        ThreatIntelSyncStatus again = synchronise();
        long sameMillis = elapsed(started);
        assertThat(again.status()).isEqualTo(ThreatIntelSyncStatus.State.SYNCED);
        assertThat(intel.count()).isEqualTo(LISTED);

        System.out.printf(Locale.ROOT, "KEV-BENCH engine=%s listed=%d first=%d ms same-catalogue=%d ms%n",
                ENGINE.name().toLowerCase(Locale.ROOT), LISTED, firstMillis, sameMillis);
    }

    @Test
    @DisplayName("a backlog of several pages is re-evaluated whole, and each newly listed issue announced once")
    void aBacklogOfSeveralPages() {
        List<IssueEntity> open = openIssues(OPEN_ISSUES);
        when(source.fetch()).thenReturn(catalogue(LISTED, RELEASED));

        long started = System.nanoTime();
        ThreatIntelSyncStatus first = synchronise();
        long firstMillis = elapsed(started);

        assertThat(first.backlogUpdatedCount()).isEqualTo(PROMOTED);
        assertThat(issues.findById(open.get(2).getId()).orElseThrow().isKev()).isTrue();
        assertThat(issues.findById(open.get(3).getId()).orElseThrow().isKev()).isFalse();
        assertThat(issues.findById(open.getLast().getId()).orElseThrow().isKev()).isEqualTo((OPEN_ISSUES - 1) % 2 == 0);
        assertThat(announced()).hasSize(PROMOTED).doesNotHaveDuplicates();

        Mockito.clearInvocations(siem);
        assertThat(synchronise().backlogUpdatedCount()).isZero();
        assertThat(announced()).isEmpty();

        System.out.printf(Locale.ROOT, "KEV-BENCH engine=%s listed=%d open-issues=%d first-with-backlog=%d ms%n",
                ENGINE.name().toLowerCase(Locale.ROOT), LISTED, OPEN_ISSUES, firstMillis);
    }

    /**
     * Two synchronisations walking the backlog at once, with the interleaving forced: the first is held
     * inside its first page — flags written, not committed — while the second is started. Each page
     * takes the sync row's lock before it reads, so the second waits and then reads the first one's
     * flags; without it, the second reads the flags as they were and announces the same issues again.
     */
    @Test
    @DisplayName("two synchronisations at once announce each newly listed issue once")
    void twoSynchronisationsAnnounceOnce() throws Exception {
        openIssues(OPEN_ISSUES);
        when(source.fetch()).thenReturn(catalogue(LISTED, RELEASED));

        CountDownLatch firstWrote = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondReached = new CountDownLatch(1);
        AtomicBoolean held = new AtomicBoolean();
        doAnswer(call -> {
                    if (Thread.currentThread().getName().equals("second")) {
                        secondReached.countDown();
                        return call.callRealMethod();
                    }
                    Object result = call.callRealMethod();
                    if (held.compareAndSet(false, true)) {
                        firstWrote.countDown();
                        assertThat(releaseFirst.await(60, TimeUnit.SECONDS)).isTrue();
                    }
                    return result;
                })
                .when(catalog)
                .recordExploitation(any());

        ExecutorService first = Executors.newSingleThreadExecutor(runnable -> new Thread(runnable, "first"));
        ExecutorService second = Executors.newSingleThreadExecutor(runnable -> new Thread(runnable, "second"));
        try {
            Future<ThreatIntelSyncStatus> one = first.submit(this::synchronise);
            assertThat(firstWrote.await(60, TimeUnit.SECONDS)).isTrue();
            Future<ThreatIntelSyncStatus> two = second.submit(this::synchronise);
            // Under the lock the second cannot reach its first page's write while the first is held;
            // without it, it gets there at once. Waited for, not assumed — and the first released
            // either way, before the engine's lock wait could time out.
            boolean overtook = secondReached.await(1, TimeUnit.SECONDS);
            releaseFirst.countDown();

            long updated = one.get(120, TimeUnit.SECONDS).backlogUpdatedCount()
                    + two.get(120, TimeUnit.SECONDS).backlogUpdatedCount();
            assertThat(announced()).as("announced to the SIEM").doesNotHaveDuplicates().hasSize(PROMOTED);
            assertThat(updated).isEqualTo(PROMOTED);
            assertThat(overtook).as("the second synchronisation read the backlog while the first held a page").isFalse();
        } finally {
            releaseFirst.countDown();
            first.shutdownNow();
            second.shutdownNow();
        }
    }

    /** The messages of every {@code CRITICAL_KEV_DETECTED} queued since the spy was last cleared. */
    private List<String> announced() {
        ArgumentCaptor<CefEvent> events = ArgumentCaptor.forClass(CefEvent.class);
        verify(siem, atLeast(0)).enqueue(events.capture());
        return events.getAllValues().stream()
                .filter(event -> event.eventType() == SecurityEventType.CRITICAL_KEV_DETECTED)
                .map(CefEvent::message)
                .toList();
    }

    /** Open issues on consecutive rows, none flagged: those on an even row are on a listed CVE. */
    private List<IssueEntity> openIssues(int count) {
        List<IssueEntity> created = new ArrayList<>();
        for (int row = 0; row < count; row++) {
            IssueEntity issue = new IssueEntity();
            issue.setType("vulnerability");
            issue.setIdentifier(cve(row));
            issue.setFingerprint("fp-kev-" + row + "-" + System.nanoTime());
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

    private ThreatIntelSyncStatus synchronise() {
        return feed.syncThreatIntel(new RequestActor("lead", null, null),
                ThreatIntelFeedService.Origin.THREAT_INTELLIGENCE_SCREEN);
    }

    /** {@code listed} CVE, the even rows: an issue on an odd row is on a CVE the catalogue does not list. */
    private static KevCatalog catalogue(int listed, Instant released) {
        Map<String, Instant> added = new LinkedHashMap<>();
        for (int entry = 0; entry < listed; entry++) {
            added.put(cve(entry * 2), added(entry * 2));
        }
        return new KevCatalog("2026.09.26", released, added);
    }

    private static Instant added(int row) {
        return Instant.parse("2021-12-10T00:00:00Z").plusSeconds(86_400L * (row % 1_000));
    }

    private static String cve(int row) {
        return String.format(Locale.ROOT, "CVE-2020-%04d", row);
    }

    private static long elapsed(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }
}
