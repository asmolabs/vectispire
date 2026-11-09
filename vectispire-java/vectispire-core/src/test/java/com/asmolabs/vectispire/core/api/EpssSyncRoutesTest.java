package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.threatintel.EpssFiles;
import com.asmolabs.vectispire.core.threatintel.ThreatIntelFeedService;
import com.asmolabs.vectispire.core.threatintel.internal.EpssFileSource;
import com.asmolabs.vectispire.core.threatintel.internal.KevCatalogSource;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * FIRST's EPSS file: synchronised through the routes and the schedule, stored, and applied to the
 * backlog — in place of the per-scan question to {@code api.first.org} it replaces.
 *
 * <p>The file is stood in for at {@link EpssFileSource}, the one place that downloads it, with files
 * built as FIRST publishes them; everything from the bytes on is the real parser, the real
 * generations and the real tables.
 */
@DisplayName("FIRST's EPSS file, synchronised")
class EpssSyncRoutesTest extends ApiTestBase {

    private static final int ROWS = 100_010;
    private static final Instant TODAY = Instant.parse("2026-09-27T12:00:21Z");
    private static final Instant YESTERDAY = TODAY.minusSeconds(24 * 3600);

    @Autowired
    private IssueRepository issuesRepo;

    @Autowired
    private EpssScoreRepository scores;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private ThreatIntelFeedService feed;

    @MockitoBean
    private EpssFileSource source;

    @MockitoBean
    private KevCatalogSource catalogue;

    @BeforeEach
    void aCatalogue() {
        when(catalogue.fetch()).thenReturn(new KevCatalog("2026.09.27", TODAY, Map.of("CVE-2021-44228", TODAY)));
        when(source.location()).thenReturn("https://epss.example.invalid/epss_scores-current.csv.gz");
    }

    @Test
    @DisplayName("before the first synchronisation the status says so, and no CVE has a score")
    void neverSynchronised() throws Exception {
        mvc.perform(authenticated(get("/api/v1/threat-intel/status"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.epss.status").value("NEVER_SYNCED"))
                .andExpect(jsonPath("$.epss.lastSyncedAt").doesNotExist())
                .andExpect(jsonPath("$.epss.totalScored").value(0))
                .andExpect(jsonPath("$.epss.inProgress").value(false));
        // Unknown, not zero: a record with a probability of 0 would be a measurement nobody made.
        mvc.perform(authenticated(get("/api/v1/epss/cve/" + EpssFiles.cve(7)), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("reads the whole file, stores it with its model and date, and re-scores the open issues it scores")
    void synchronisesAndRescores() throws Exception {
        IssueEntity open = issue(EpssFiles.cve(7), "open", null);
        IssueEntity unscoredByTheFile = issue("CVE-2031-9999", "open", 0.33);
        IssueEntity closed = issue(EpssFiles.cve(8), "resolved", 0.5);
        file(EpssFiles.gzip(ROWS, "v2025.03.14", TODAY, 0));

        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), asCiso()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SYNCED"))
                .andExpect(jsonPath("$.epss.status").value("SYNCED"))
                .andExpect(jsonPath("$.epss.modelVersion").value("v2025.03.14"))
                .andExpect(jsonPath("$.epss.scoreDate").value(TODAY.toString()))
                .andExpect(jsonPath("$.epss.totalScored").value(ROWS))
                .andExpect(jsonPath("$.epss.backlogUpdatedCount").value(1))
                .andExpect(jsonPath("$.epss.lastError").doesNotExist());

        assertThat(issuesRepo.findById(open.getId()).orElseThrow().getEpssScore()).isEqualTo(EpssFiles.score(7, 0));
        // Only a known score replaces one: a CVE the file does not score keeps its figure.
        assertThat(issuesRepo.findById(unscoredByTheFile.getId()).orElseThrow().getEpssScore()).isEqualTo(0.33);
        // Processing reads leave closed issues alone, as the KEV re-evaluation does.
        assertThat(issuesRepo.findById(closed.getId()).orElseThrow().getEpssScore()).isEqualTo(0.5);
        mvc.perform(authenticated(get("/api/v1/epss/cve/" + EpssFiles.cve(7).toLowerCase()), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.epssScore").value(EpssFiles.score(7, 0)))
                .andExpect(jsonPath("$.epssPercentile").value(EpssFiles.score(7, 0)))
                .andExpect(jsonPath("$.isKev").value(false));
        assertThat(scores.count()).as("one generation, and only one").isEqualTo(ROWS);

        // One entry per feed, each saying what it read.
        assertThat(auditLog.findAll())
                .filteredOn(entry -> AuditOperation.THREAT_INTEL_SYNCED.wireName().equals(entry.getOperationType()))
                .map(AuditLogEntity::getDescription)
                .anySatisfy(entry -> assertThat(entry).startsWith("CISA KEV catalogue synchronized"))
                .anySatisfy(entry -> assertThat(entry).isEqualTo("EPSS scores synchronized from the threat intelligence "
                        + "screen (model v2025.03.14, scores of " + TODAY + ", " + ROWS + " CVE, updated=1)"));
    }

    @Test
    @DisplayName("a newer file replaces the scores; the one it replaced is kept until the next")
    void aNewerFileReplaces() throws Exception {
        IssueEntity open = issue(EpssFiles.cve(7), "open", null);
        file(EpssFiles.gzip(ROWS, "v2025.03.14", YESTERDAY, 0));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso())).andExpect(status().isOk());

        file(EpssFiles.gzip(ROWS + 5, "v2025.03.14", TODAY, 500));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso()))
                .andExpect(jsonPath("$.epss.status").value("SYNCED"))
                .andExpect(jsonPath("$.epss.scoreDate").value(TODAY.toString()))
                .andExpect(jsonPath("$.epss.totalScored").value(ROWS + 5));

        assertThat(issuesRepo.findById(open.getId()).orElseThrow().getEpssScore()).isEqualTo(EpssFiles.score(7, 500));
        // Yesterday's generation is kept a file longer, for a reader that read the row before the switch.
        assertThat(scores.count()).isEqualTo(ROWS + ROWS + 5);
        mvc.perform(authenticated(get("/api/v1/epss/cve/" + EpssFiles.cve(7)), asCiso()))
                .andExpect(jsonPath("$.epssScore").value(EpssFiles.score(7, 500)));

        file(EpssFiles.gzip(ROWS + 9, "v2025.03.14", TODAY.plusSeconds(86_400), 900));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso())).andExpect(status().isOk());
        assertThat(scores.count()).as("the day before yesterday's generation is gone").isEqualTo(ROWS + 5 + ROWS + 9);
    }

    @Test
    @DisplayName("a file older than the one in use is refused, recorded as failed, and the scores in use stay")
    void anOlderFileIsRefused() throws Exception {
        IssueEntity open = issue(EpssFiles.cve(7), "open", null);
        file(EpssFiles.gzip(ROWS, "v2025.03.14", TODAY, 0));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso())).andExpect(status().isOk());

        // A mirror restored from last week's copy.
        file(EpssFiles.gzip(ROWS, "v2025.03.14", TODAY.minusSeconds(7 * 24 * 3600), 900));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso()))
                .andExpect(jsonPath("$.epss.status").value("FAILED"))
                .andExpect(jsonPath("$.epss.lastError").value(Matchers.containsString("older than the one in use")))
                .andExpect(jsonPath("$.epss.scoreDate").value(TODAY.toString()))
                .andExpect(jsonPath("$.epss.totalScored").value(ROWS));

        assertThat(issuesRepo.findById(open.getId()).orElseThrow().getEpssScore()).isEqualTo(EpssFiles.score(7, 0));
        assertThat(scores.count()).as("nothing of the refused file was written").isEqualTo(ROWS);
        assertThat(auditLog.findAll()).map(AuditLogEntity::getDescription)
                .anySatisfy(entry -> assertThat(entry).startsWith("EPSS scores synchronization from the EPSS screen "
                        + "failed: the file read (scores of"));
    }

    @Test
    @DisplayName("a download cut short is refused, and what it had written is discarded")
    void aTruncatedFileIsRefused() throws Exception {
        file(EpssFiles.gzip(ROWS, "v2025.03.14", YESTERDAY, 0));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso())).andExpect(status().isOk());

        file(EpssFiles.truncated(EpssFiles.gzip(ROWS, "v2025.03.14", TODAY, 300)));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso()))
                .andExpect(jsonPath("$.epss.status").value("FAILED"))
                .andExpect(jsonPath("$.epss.lastError").value(Matchers.containsString("cut short")))
                .andExpect(jsonPath("$.epss.scoreDate").value(YESTERDAY.toString()));

        // Half the file had been written under a generation of its own before the archive ended.
        assertThat(scores.count()).as("the half-written generation is gone").isEqualTo(ROWS);
        mvc.perform(authenticated(get("/api/v1/epss/cve/" + EpssFiles.cve(7)), asAdmin()))
                .andExpect(jsonPath("$.epssScore").value(EpssFiles.score(7, 0)));
    }

    @Test
    @DisplayName("a whole file a tenth smaller than the one in use is refused as incomplete")
    void aMuchSmallerFileIsRefused() throws Exception {
        file(EpssFiles.gzip(120_000, "v2025.03.14", YESTERDAY, 0));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso())).andExpect(status().isOk());

        file(EpssFiles.gzip(105_000, "v2025.03.14", TODAY, 0));
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso()))
                .andExpect(jsonPath("$.epss.status").value("FAILED"))
                .andExpect(jsonPath("$.epss.lastError").value(Matchers.containsString("incomplete")))
                .andExpect(jsonPath("$.epss.totalScored").value(120_000));
        assertThat(scores.count()).isEqualTo(120_000);
    }

    @Test
    @DisplayName("the same file again is confirmed, not rewritten")
    void theSameFileIsConfirmed() throws Exception {
        byte[] file = EpssFiles.gzip(ROWS, "v2025.03.14", TODAY, 0);
        file(file);
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso())).andExpect(status().isOk());
        long generation = scores.findAll().getFirst().getGeneration();

        mvc.perform(authenticated(post("/api/v1/epss/sync"), asCiso()))
                .andExpect(jsonPath("$.epss.status").value("SYNCED"));

        assertThat(scores.countByGeneration(generation)).as("the generation in use is still the first").isEqualTo(ROWS);
        assertThat(auditLog.findAll()).map(AuditLogEntity::getDescription)
                .anySatisfy(entry -> assertThat(entry).startsWith("EPSS scores confirmed from the EPSS screen: the file "
                        + "read is the one in use"));
    }

    @Test
    @DisplayName("an unreachable source fails visibly, and is audited as a failure")
    void anOutageIsAFailure() throws Exception {
        when(source.fetch()).thenThrow(new IllegalStateException("EPSS file: connection refused"));

        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), asCiso()))
                .andExpect(jsonPath("$.status").value("SYNCED"))
                .andExpect(jsonPath("$.epss.status").value("FAILED"))
                .andExpect(jsonPath("$.epss.lastError").value("EPSS file: connection refused"))
                .andExpect(jsonPath("$.epss.lastAttemptAt").isString())
                .andExpect(jsonPath("$.epss.lastSyncedAt").doesNotExist());
        assertThat(auditLog.findAll()).map(AuditLogEntity::getDescription)
                .anySatisfy(entry -> assertThat(entry).isEqualTo("EPSS scores synchronization from the threat "
                        + "intelligence screen failed: EPSS file: connection refused (scores in use kept: none)"));
    }

    @Test
    @DisplayName("the file is fetched with no transaction open")
    void theFetchHoldsNoTransaction() {
        AtomicReference<Boolean> open = new AtomicReference<>();
        byte[] file = EpssFiles.gzip(ROWS, "v2025.03.14", TODAY, 0);
        when(source.fetch()).thenAnswer(call -> {
            open.set(TransactionSynchronizationManager.isActualTransactionActive());
            return file;
        });

        feed.syncThreatIntel(new RequestActor("lead", null, null), ThreatIntelFeedService.Origin.THREAT_INTELLIGENCE_SCREEN);

        assertThat(open.get()).as("a transaction was open during the fetch").isFalse();
    }

    @Test
    @DisplayName("the schedule synchronises when the file is due, once across instances, and retries a failure later")
    void theScheduleSynchronisesOnce() {
        when(source.fetch()).thenThrow(new IllegalStateException("unreachable"));
        assertThat(feed.syncEpssIfDue()).get().extracting(result -> result.epss().status())
                .isEqualTo(ThreatIntelSyncStatus.State.FAILED);
        // The next turn — or another instance's — is inside the retry interval.
        assertThat(feed.syncEpssIfDue()).isEmpty();
        verify(source, times(1)).fetch();
        assertThat(auditLog.findAll())
                .filteredOn(entry -> "system".equals(entry.getUserId()))
                .map(AuditLogEntity::getDescription)
                .singleElement()
                .asString()
                .startsWith("EPSS scores synchronization from the maintenance schedule failed");
    }

    private void file(byte[] bytes) {
        when(source.fetch()).thenReturn(bytes);
    }

    private IssueEntity issue(String cve, String state, Double epss) {
        IssueEntity issue = new IssueEntity();
        issue.setType("vulnerability");
        issue.setIdentifier(cve);
        issue.setFingerprint("fp-" + cve + "-" + System.nanoTime());
        issue.setPackageName("openssl");
        issue.setSource("grype");
        issue.setSeverity("high");
        issue.setState(state);
        issue.setEpssScore(epss);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTriageStatus("untriaged");
        return issuesRepo.save(issue);
    }
}
