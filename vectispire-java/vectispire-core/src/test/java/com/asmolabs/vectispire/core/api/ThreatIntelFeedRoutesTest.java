package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.threatintel.ThreatIntelFeedService;
import com.asmolabs.vectispire.core.threatintel.internal.KevCatalogSource;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The CISA KEV catalogue: synchronised through the routes and the schedule, stored, and applied to
 * the backlog.
 *
 * <p>The catalogue is stood in for at {@link KevCatalogSource}, the one place that reaches CISA — so
 * everything from the parsed document on is the real service, the real transactions and the real
 * tables. It used to be a list of ten records typed into the service, and this test asserted that
 * the "sync" found ten; that is what it now proves cannot happen.
 */
@DisplayName("the CISA KEV catalogue, synchronised")
class ThreatIntelFeedRoutesTest extends ApiTestBase {

    private static final Instant RELEASED = Instant.parse("2026-09-26T15:00:00Z");

    @Autowired
    private IssueRepository issuesRepo;

    @Autowired
    private ThreatIntelRepository intel;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private ThreatIntelFeedService feed;

    @MockitoBean
    private KevCatalogSource source;

    @MockitoSpyBean
    private SiemEvents siem;

    @Test
    @DisplayName("before anything was synchronised the status says so, and lists nothing")
    void neverSynchronised() throws Exception {
        mvc.perform(authenticated(get("/api/v1/threat-intel/status"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("NEVER_SYNCED"))
                .andExpect(jsonPath("$.lastSyncedAt").doesNotExist())
                .andExpect(jsonPath("$.totalKev").value(0));

        // The ten typed-in records answered this before: Log4Shell was "KEV" on an installation that
        // had never read the catalogue.
        mvc.perform(authenticated(get("/api/v1/epss/cve/CVE-2021-44228"), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("reads the catalogue, stores it with its date, and promotes the open issues it lists")
    void synchronisesAndPromotes() throws Exception {
        IssueEntity log4shell = issue("CVE-2021-44228", false);
        catalogue(RELEASED, "CVE-2021-44228", "CVE-2023-34362");

        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SYNCED"))
                .andExpect(jsonPath("$.totalKev").value(2))
                .andExpect(jsonPath("$.kevCatalogVersion").value("2026.09.26"))
                .andExpect(jsonPath("$.kevReleasedAt").isString())
                .andExpect(jsonPath("$.lastSyncedAt").isString())
                .andExpect(jsonPath("$.backlogUpdatedCount").value(1));

        assertThat(issuesRepo.findById(log4shell.getId()).orElseThrow().isKev()).isTrue();
        // The promotion is a security event, and this is the only place it is raised.
        verify(siem).enqueue(argThat(event -> event.eventType() == SecurityEventType.CRITICAL_KEV_DETECTED
                && event.message().contains("CVE-2021-44228")));

        mvc.perform(authenticated(get("/api/v1/threat-intel/status"), asAdmin()))
                .andExpect(jsonPath("$.status").value("SYNCED"))
                .andExpect(jsonPath("$.kevReleasedAt").value(RELEASED.toString()));
        mvc.perform(authenticated(get("/api/v1/epss/cve/CVE-2021-44228"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isKev").value(true))
                // No EPSS figure is invented for it: the catalogue carries none.
                .andExpect(jsonPath("$.epssScore").doesNotExist());
        // And a scan asks the same table: the query a scan's enrichment runs finds the stored entry.
        assertThat(intel.exploitedAmong(List.of("cve-2021-44228", "cve-2099-0001"))).containsExactly("CVE-2021-44228");
    }

    @Test
    @DisplayName("an issue flagged exploited whose CVE the catalogue does not list is un-flagged")
    void aCveTheCatalogueDoesNotListIsNotExploited() throws Exception {
        // Flagged by the typed-in list this replaced, which counted CVEs CISA does not.
        IssueEntity notListed = issue("CVE-2024-6387", true);
        catalogue(RELEASED, "CVE-2021-44228");

        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), asAdmin())).andExpect(status().isOk());

        assertThat(issuesRepo.findById(notListed.getId()).orElseThrow().isKev()).isFalse();
    }

    @Test
    @DisplayName("an unreachable catalogue fails visibly, keeps the one in use, and is audited as a failure")
    void aFailureKeepsTheCatalogueInUse() throws Exception {
        IssueEntity log4shell = issue("CVE-2021-44228", false);
        catalogue(RELEASED, "CVE-2021-44228");
        String lead = asCiso();
        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), lead)).andExpect(status().isOk());

        when(source.fetch()).thenThrow(new IllegalStateException("KEV catalogue: connection refused"));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), lead))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.lastError").value("KEV catalogue: connection refused"))
                .andExpect(jsonPath("$.totalKev").value(1))
                .andExpect(jsonPath("$.lastSyncedAt").isString());

        // An outage is not a catalogue listing nothing: the flag it set stays.
        assertThat(issuesRepo.findById(log4shell.getId()).orElseThrow().isKev()).isTrue();
        assertThat(intel.findByCveIdIgnoreCase("CVE-2021-44228")).get().extracting(e -> e.isKev()).isEqualTo(true);
        assertThat(auditLog.findAll()).map(AuditLogEntity::getDescription)
                .anySatisfy(entry -> assertThat(entry).contains("from the EPSS screen failed: KEV catalogue: connection refused"));
    }

    @Test
    @DisplayName("a catalogue older than the one in use is refused, not applied")
    void anOlderCatalogueIsRefused() throws Exception {
        IssueEntity log4shell = issue("CVE-2021-44228", false);
        catalogue(RELEASED, "CVE-2021-44228");
        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), asAdmin())).andExpect(status().isOk());

        // A mirror restored from last month's copy: applied, it would un-flag everything listed since.
        catalogue(RELEASED.minusSeconds(30L * 24 * 3600), "CVE-2019-0001");
        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), asAdmin()))
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.lastError").value(org.hamcrest.Matchers.containsString("older than the one in use")));

        assertThat(issuesRepo.findById(log4shell.getId()).orElseThrow().isKev()).isTrue();
        assertThat(intel.findByCveIdIgnoreCase("CVE-2019-0001")).isEmpty();
    }

    @Test
    @DisplayName("the catalogue is fetched with no transaction open")
    void theFetchHoldsNoTransaction() {
        AtomicReference<Boolean> open = new AtomicReference<>();
        when(source.fetch()).thenAnswer(call -> {
            open.set(TransactionSynchronizationManager.isActualTransactionActive());
            return new KevCatalog("2026.09.26", RELEASED, Map.of("CVE-2021-44228", RELEASED));
        });

        feed.syncThreatIntel(new com.asmolabs.vectispire.core.audit.RequestActor("lead", null, null),
                ThreatIntelFeedService.Origin.THREAT_INTELLIGENCE_SCREEN);

        assertThat(open.get()).as("a transaction was open during the fetch").isFalse();
    }

    @Test
    @DisplayName("the schedule synchronises when the catalogue is due, once across instances, and is audited")
    void theScheduleSynchronisesOnce() {
        catalogue(RELEASED, "CVE-2021-44228");

        assertThat(feed.syncIfDue()).get().extracting(ThreatIntelSyncStatus::status)
                .isEqualTo(ThreatIntelSyncStatus.State.SYNCED);
        // The next turn — or another instance's — finds a fresh catalogue and does nothing.
        assertThat(feed.syncIfDue()).isEmpty();

        verify(source, times(1)).fetch();
        assertThat(auditLog.findAll())
                .filteredOn(entry -> AuditOperation.THREAT_INTEL_SYNCED.wireName().equals(entry.getOperationType()))
                .filteredOn(entry -> "system".equals(entry.getUserId()))
                .singleElement()
                .extracting(AuditLogEntity::getDescription)
                .asString()
                .contains("from the maintenance schedule");
    }

    @Test
    @DisplayName("a failed scheduled attempt is not retried by every turn, but after the retry interval")
    void aFailedScheduleWaitsBeforeRetrying() {
        when(source.fetch()).thenThrow(new IllegalStateException("unreachable"));

        assertThat(feed.syncIfDue()).get().extracting(ThreatIntelSyncStatus::status)
                .isEqualTo(ThreatIntelSyncStatus.State.FAILED);
        assertThat(feed.syncIfDue()).isEmpty();

        verify(source, times(1)).fetch();
        verify(siem, never()).enqueue(any());
    }

    private void catalogue(Instant released, String... cves) {
        Map<String, Instant> added = new java.util.LinkedHashMap<>();
        for (String cve : cves) {
            added.put(cve, Instant.parse("2021-12-10T00:00:00Z"));
        }
        when(source.fetch()).thenReturn(new KevCatalog("2026.09.26", released, added));
    }

    private IssueEntity issue(String cve, boolean kev) {
        IssueEntity issue = new IssueEntity();
        issue.setType("vulnerability");
        issue.setIdentifier(cve);
        issue.setFingerprint("fp-" + cve + "-" + System.nanoTime());
        issue.setPackageName("log4j-core");
        issue.setSource("grype");
        issue.setSeverity("critical");
        issue.setState("open");
        issue.setKev(kev);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTriageStatus("untriaged");
        return issuesRepo.save(issue);
    }
}
