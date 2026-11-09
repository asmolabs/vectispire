package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventRaised;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * A triage and a scan writing one issue at once, on a real engine and on two threads.
 *
 * <p><b>What was lost.</b> A scan read the target's issues when its write began and saved them whole
 * at its end; a triage committed in between was put back to what the scan had read — the decision gone,
 * with no error and no log line. The issue's revision (V89) refuses the second writer now, and each side
 * answers it its own way: the scan folds again from what is committed, the triage is refused (409).
 *
 * <p><b>The interleaving is forced, not hoped for.</b> The scan's write is held between its read of the
 * issues and its first statement on them — by a listener of the leak it announces, which runs in its
 * transaction at exactly that point — while the triage commits on another thread; and the triage of the
 * second case reads the issue in a transaction the scan then commits under.
 */
@SpringBootTest(classes = VectispireApplication.class)
@Import(TriageDuringScanIntegrationTest.Hold.class)
@DisplayName("a triage during a scan, on a real engine")
class TriageDuringScanIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

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

    /** What the scan's thread runs when it announces a leak, once — the test's hold inside the scan's write. */
    static final AtomicReference<Runnable> DURING_SCAN = new AtomicReference<>();

    /** How many times the scan's write announced a leak: one per attempt to fold it. */
    static final AtomicInteger FOLDS = new AtomicInteger();

    @TestConfiguration
    static class Hold {
        @Bean
        HoldListener holdListener() {
            return new HoldListener();
        }
    }

    static class HoldListener {
        @EventListener
        void during(SecurityEventRaised raised) {
            FOLDS.incrementAndGet();
            Runnable once = DURING_SCAN.getAndSet(null);
            if (once != null) {
                once.run();
            }
        }
    }

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private IssueTriageService triage;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private TriageEventRepository history;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TransactionTemplate transactions;

    private final ExecutorService person = Executors.newSingleThreadExecutor();

    private long repositoryId;

    @BeforeEach
    void seed() {
        DURING_SCAN.set(null);
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName("triage-during-scan");
        repository.setUrl("https://example.invalid/triage-during-scan-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        repositoryId = repositories.save(repository).getId();
    }

    @AfterEach
    void release() {
        DURING_SCAN.set(null);
        person.shutdownNow();
    }

    @Test
    @DisplayName("a triage committed while a scan writes is kept, and the scan completes, folding once more")
    void theScanFoldsAgain() throws Exception {
        long issueId = firstScan();

        // The second scan sees the leak again and a new one, whose announcement holds its write after
        // the issues were read and before any of them is written: the person decides then, and commits.
        DURING_SCAN.set(() -> {
            Future<?> decided = person.submit(() -> triage.triage(issueId, affected()));
            try {
                decided.get(1, TimeUnit.MINUTES);
            } catch (Exception failed) {
                throw new IllegalStateException("The triage beside the scan failed.", failed);
            }
        });
        FOLDS.set(0);
        long secondScan = scan();
        assertThat(dispatcher.acceptAgentResult(secondScan, agent(secondScan), leaks("first", "second"))).isTrue();

        IssueEntity issue = issues.findById(issueId).orElseThrow();
        assertThat(issue.getTriageStatus()).as("the person's decision").isEqualTo(TriageStatus.AFFECTED.wireName());
        assertThat(issue.getTriagedBy()).isEqualTo("alice");
        assertThat(issue.getLastSeenScanId()).as("the scan's sighting").isEqualTo(secondScan);
        assertThat(issue.getTimesSeen()).as("counted once, by the attempt that committed").isEqualTo(2);
        assertThat(FOLDS.get()).as("the scan folded again after the refusal").isEqualTo(2);
        assertThat(scans.findById(secondScan).orElseThrow().getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        assertThat(issues.findAll()).filteredOn(each -> repositoryIdOf(each) == repositoryId).hasSize(2);
    }

    @Test
    @DisplayName("a triage that read the issue before a scan committed is refused as changed meanwhile, and writes nothing")
    void theTriageIsRefused() throws Exception {
        long issueId = firstScan();
        long secondScan = scan();
        int recorded = history.findByIssueIdOrderByOccurredAtAscIdAsc(issueId).size();

        assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
            // The person's transaction reads the issue as it is before the scan …
            issues.findById(issueId).orElseThrow();
            // … the scan commits on another thread, the issue read again by it …
            Future<Boolean> scanned = person.submit(
                    () -> dispatcher.acceptAgentResult(secondScan, agent(secondScan), leaks("first")));
            try {
                assertThat(scanned.get(1, TimeUnit.MINUTES)).isTrue();
            } catch (Exception failed) {
                throw new IllegalStateException("The scan beside the triage failed.", failed);
            }
            // … and the decision is written onto the row this transaction read.
            triage.triage(issueId, affected());
        })).isInstanceOf(IssueChangedMeanwhileException.class);

        IssueEntity issue = issues.findById(issueId).orElseThrow();
        assertThat(issue.getLastSeenScanId()).as("the scan's write stands").isEqualTo(secondScan);
        assertThat(issue.getTimesSeen()).isEqualTo(2);
        assertThat(issue.getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(history.findByIssueIdOrderByOccurredAtAscIdAsc(issueId)).as("no history row for a refused decision")
                .hasSize(recorded);
    }

    /** A first scan that files the leak the tests then fight over; answers its issue. */
    private long firstScan() {
        long first = scan();
        assertThat(dispatcher.acceptAgentResult(first, agent(first), leaks("first"))).isTrue();
        return issues.findAll().stream()
                .filter(each -> repositoryIdOf(each) == repositoryId)
                .findFirst().orElseThrow().getId();
    }

    private static long repositoryIdOf(IssueEntity issue) {
        return issue.getRepoId() == null ? -1 : issue.getRepoId();
    }

    private static Triage.Request affected() {
        return new Triage.Request(TriageStatus.AFFECTED, "alice", null, "Reachable from the login form.", null);
    }

    private static ScanArtifacts leaks(String... files) {
        return ScanArtifacts.builder()
                .secrets(java.util.Arrays.stream(files)
                        .map(file -> new SecretFinding("generic-api-key", "A key", "config/" + file + ".properties", 3, null))
                        .toList())
                .build(Duration.ofSeconds(1));
    }

    private final java.util.Map<Long, UUID> agents = new java.util.concurrent.ConcurrentHashMap<>();

    private AgentView agent(long scanId) {
        AgentView agent = mock(AgentView.class);
        when(agent.id()).thenReturn(agents.get(scanId));
        when(agent.name()).thenReturn("remote-1");
        return agent;
    }

    /** A scan an agent holds, as one does between its claim and its result. */
    private long scan() {
        UUID agentId = UUID.randomUUID();
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(1);
        scan.setClaimedBy(agentId.toString());
        scan.setClaimedAt(Instant.now());
        scan.setLeaseExpiresAt(Instant.now().plus(Duration.ofMinutes(10)));
        long id = scans.save(scan).getId();
        agents.put(id, agentId);
        return id;
    }
}
