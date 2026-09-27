package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * A scan's findings are scored without anything leaving the control plane.
 *
 * <p>Each scan used to ask {@code api.first.org} for the EPSS scores of the CVE it had found — the
 * list of what each repository is vulnerable to, sent to a third party on the day it was scanned.
 * This runs a result through the real dispatcher, the real ingestion and the real enrichment, with
 * the one door out replaced by a sender that fails the test at the first request, and checks the
 * finding still got its score: from the file the control plane stored.
 */
@DisplayName("ingesting a scan sends nothing outside")
class NoOutboundDuringIngestionTest extends VectispireContextTest {

    /** The one door out, replaced: whatever reaches it is recorded, and the test fails on it. */
    @MockitoBean
    private PinnedHttpSender sender;

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private FindingRepository findings;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private EpssScoreRepository epss;

    @Autowired
    private ThreatIntelSyncRepository syncs;

    @Test
    @DisplayName("the finding is scored from the stored file, and the sender is never asked")
    void scoredLocally() {
        storedScore("CVE-2026-4242", 0.61);

        UUID agentId = UUID.randomUUID();
        long scanId = claimedScan(agentId.toString());
        AgentView agent = mock(AgentView.class);
        when(agent.id()).thenReturn(agentId);
        when(agent.name()).thenReturn("remote-1");

        boolean accepted = dispatcher.acceptAgentResult(scanId, agent, ScanArtifacts.builder()
                .dependencies(List.of(new DependencyFinding(
                        "CVE-2026-4242", Severity.HIGH, "openssl", "1.1.1", "", null, null, "pkg:generic/openssl@1.1.1")))
                .build(Duration.ofSeconds(1)));

        assertThat(accepted).isTrue();
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        assertThat(findings.findAll()).filteredOn(finding -> scanId == finding.getScanId())
                .singleElement()
                .extracting(FindingEntity::getEpssScore)
                .isEqualTo(0.61);
        // Every request of the control plane goes through this bean (`ArchitectureTest`); a lookup
        // swallowed as "enrichment unavailable" would still show here.
        verifyNoInteractions(sender);
    }

    /** One stored generation holding this score, and the sync row naming it — what a synchronisation leaves. */
    private void storedScore(String cve, double score) {
        long generation = 7;
        epss.insertAll(generation, List.of(new EpssFile.Score(cve, score, 0.97)));
        Instant now = Instant.now();
        syncs.save(new ThreatIntelSyncEntity());
        syncs.claimEpss(ThreatIntelSyncEntity.SINGLETON_ID, now, now.plusSeconds(60), generation);
        assertThat(syncs.applyEpss(ThreatIntelSyncEntity.SINGLETON_ID, generation, now, "v2025.03.14", now, 1))
                .isEqualTo(1);
    }

    private long claimedScan(String worker) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/no-outbound-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(1);
        scan.setClaimedBy(worker);
        scan.setClaimedAt(Instant.now());
        scan.setLeaseExpiresAt(Instant.now().plus(Duration.ofMinutes(10)));
        return scans.save(scan).getId();
    }
}
