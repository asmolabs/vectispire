package com.asmolabs.vectispire.core.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFileSource;
import com.asmolabs.vectispire.core.threatintel.internal.KevCatalogSource;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
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
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    /** CISA's catalogue in September 2026 lists some 1,500 CVE. */
    private static final int LISTED = 1_500;

    private static final Instant RELEASED = Instant.parse("2026-09-26T15:00:00Z");

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
