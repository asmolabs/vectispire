package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * A scan result's enrichment, asked while no transaction is open.
 *
 * <p>The EPSS lookups ran inside the scan's writing transaction: one request per ninety CVE, ten
 * seconds each at worst, while the transaction held the row lock that fences a concurrent reclaim.
 * The dispatcher's ordering was already pinned with mocks; this runs a result through the real
 * dispatcher, the real transaction manager and the real ingestion, and asks the one question a mock
 * cannot answer — was a transaction actually open at the moment of the call.
 */
@DisplayName("enriching a scan's result, outside its transaction")
class EnrichmentOutsideTransactionTest extends VectispireContextTest {

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private FindingRepository findings;

    @Autowired
    private GitRepositoryRepository repositories;

    @MockitoBean
    private ScanIngestor.Enricher enricher;

    @Test
    @DisplayName("the enricher is called with no transaction open, and its answer is written with the scan")
    void theLookupHoldsNoTransaction() {
        AtomicReference<Boolean> transactionOpen = new AtomicReference<>();
        when(enricher.enrich(any())).thenAnswer(call -> {
            transactionOpen.set(TransactionSynchronizationManager.isActualTransactionActive());
            return Optional.of(new ScanIngestor.Enrichment(Map.of("CVE-2026-4242", 0.61), Set.of("CVE-2026-4242")));
        });

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
        assertThat(transactionOpen.get()).as("a transaction was open during the lookup").isFalse();
        // And the answer was not lost on the way: asked outside, applied inside, written together.
        assertThat(findings.findAll()).filteredOn(finding -> scanId == finding.getScanId())
                .singleElement()
                .satisfies(finding -> {
                    assertThat(finding.getEpssScore()).isEqualTo(0.61);
                    assertThat(finding.getIsKev()).isTrue();
                });
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
    }

    /** A scan an agent holds the lease of, as the claim leaves it. */
    private long claimedScan(String worker) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/enrichment-" + System.nanoTime() + ".git");
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
