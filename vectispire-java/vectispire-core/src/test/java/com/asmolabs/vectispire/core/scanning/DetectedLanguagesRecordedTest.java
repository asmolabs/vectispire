package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.plugins.Language;
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
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The census's languages kept on the scan by both executors, and read back from each repository's
 * newest completed scan — through the real dispatcher, ingestion and database.
 *
 * <p>The built-in worker and an agent reach the same write by two doors; a column set on one of them
 * only would show every repository the other scanned as unknown. Only the runner is replaced.
 */
@DisplayName("the languages a scan found, recorded and read back")
class DetectedLanguagesRecordedTest extends VectispireContextTest {

    @MockitoBean
    private ScanRunner runner;

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ScanCatalog catalog;

    @Autowired
    private GitRepositoryRepository repositories;

    private static ScanArtifacts counted(Set<Language> languages) {
        return ScanArtifacts.builder().secrets(List.of()).languages(languages).build(Duration.ofSeconds(1));
    }

    @Test
    @DisplayName("the built-in worker's scan records its census, sorted, in the manifests' vocabulary")
    void theBuiltInWorker() {
        long scanId = scan(repository(), ScanStatus.PENDING, null);
        when(runner.run(any())).thenReturn(counted(Set.of(Language.TYPESCRIPT, Language.JAVA)));

        assertThat(dispatcher.dispatch("built-in-" + UUID.randomUUID(), 1, List.of()).completed()).isEqualTo(1);

        assertThat(scans.findById(scanId).orElseThrow().getDetectedLanguages()).isEqualTo("java,typescript");
    }

    @Test
    @DisplayName("an agent's result records its census; one without a census records unknown, not none")
    void anAgentsResult() {
        UUID agentId = UUID.randomUUID();
        AgentView agent = mock(AgentView.class);
        when(agent.id()).thenReturn(agentId);
        when(agent.name()).thenReturn("remote-1");

        long counted = scan(repository(), ScanStatus.SCANNING, agentId.toString());
        assertThat(dispatcher.acceptAgentResult(counted, agent, counted(Set.of()))).isTrue();
        assertThat(scans.findById(counted).orElseThrow().getDetectedLanguages())
                .describedAs("a whole census that saw no language")
                .isEmpty();

        long uncounted = scan(repository(), ScanStatus.SCANNING, agentId.toString());
        assertThat(dispatcher.acceptAgentResult(uncounted, agent,
                ScanArtifacts.builder().secrets(List.of()).build(Duration.ofSeconds(1)))).isTrue();
        assertThat(scans.findById(uncounted).orElseThrow().getDetectedLanguages()).isNull();
    }

    @Test
    @DisplayName("each repository answers from its newest completed scan: never an older one's, never a failed one's")
    void theNewestCompletedScanAnswers() {
        long current = repository();
        stored(current, ScanStatus.COMPLETED, "java");
        stored(current, ScanStatus.COMPLETED, "java,typescript");
        stored(current, ScanStatus.FAILED, "go");
        stored(current, ScanStatus.PENDING, null);

        long forgotten = repository();
        stored(forgotten, ScanStatus.COMPLETED, "python");
        stored(forgotten, ScanStatus.COMPLETED, null);

        long empty = repository();
        stored(empty, ScanStatus.COMPLETED, "");

        long never = repository();

        Map<Long, Set<Language>> detected = catalog.newestDetectedLanguages(List.of(current, forgotten, empty, never));

        assertThat(detected).containsEntry(current, Set.of(Language.JAVA, Language.TYPESCRIPT));
        assertThat(detected)
                .describedAs("a newest scan that recorded nothing is unknown, not last month's Python")
                .doesNotContainKey(forgotten);
        assertThat(detected).containsEntry(empty, Set.of());
        assertThat(detected).doesNotContainKey(never);
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/languages-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void stored(long repositoryId, ScanStatus status, String languages) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setDetectedLanguages(languages);
        scans.save(scan);
    }

    private long scan(long repositoryId, ScanStatus status, String claimedBy) {
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
