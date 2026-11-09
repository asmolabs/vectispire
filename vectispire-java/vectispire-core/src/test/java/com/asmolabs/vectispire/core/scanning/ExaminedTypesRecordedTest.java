package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * Both executors' results keep what the scan examined — through the real dispatcher, ingestion and
 * database (decision 0032, §6).
 *
 * <p>The built-in worker and an agent reach the same write by two doors, and a column set on one path
 * only is the defect this pins: a checklist would read every repository the built-in worker scanned as
 * unrecorded, or every one an agent scanned. Only the runner is replaced — it would start containers.
 */
@DisplayName("recording what a scan examined, on both executors")
class ExaminedTypesRecordedTest extends VectispireContextTest {

    @MockitoBean
    private ScanRunner runner;

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    /** Secrets clean, IaC clean, the dependency step failed: two of the three examined the tree. */
    private static ScanArtifacts twoOfThree() {
        return ScanArtifacts.builder()
                .secrets(List.of())
                .iac(List.of())
                .failed("dependencies", "the matcher exited with 1")
                .build(Duration.ofSeconds(1));
    }

    @Test
    @DisplayName("the built-in worker's scan records the steps that produced, and not the one that failed")
    void theBuiltInWorker() {
        long scanId = scan(ScanStatus.PENDING, null);
        when(runner.run(any())).thenReturn(twoOfThree());

        ScanDispatcher.Dispatched round = dispatcher.dispatch("built-in-" + UUID.randomUUID(), 1, List.of());

        assertThat(round.completed()).isEqualTo(1);
        ScanEntity scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        assertThat(scan.getExaminedTypes()).isEqualTo("iac,secret");
    }

    @Test
    @DisplayName("an agent's result records the steps that produced, and not the one that failed")
    void anAgentsResult() {
        UUID agentId = UUID.randomUUID();
        long scanId = scan(ScanStatus.SCANNING, agentId.toString());
        AgentView agent = mock(AgentView.class);
        when(agent.id()).thenReturn(agentId);
        when(agent.name()).thenReturn("remote-1");

        assertThat(dispatcher.acceptAgentResult(scanId, agent, twoOfThree())).isTrue();

        assertThat(scans.findById(scanId).orElseThrow().getExaminedTypes()).isEqualTo("iac,secret");
    }

    private long scan(ScanStatus status, String claimedBy) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/examined-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        if (claimedBy != null) {
            scan.setAttempts(1);
            scan.setClaimedBy(claimedBy);
            scan.setClaimedAt(Instant.now());
            scan.setLeaseExpiresAt(Instant.now().plus(Duration.ofMinutes(10)));
        }
        return scans.save(scan).getId();
    }
}
