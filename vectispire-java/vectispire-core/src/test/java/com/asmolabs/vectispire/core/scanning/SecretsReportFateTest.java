package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.GitClone;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.Daemon;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * A secret found, then a report gitleaks did not write, through the built-in worker as it runs: a real
 * clone from a {@code git://} daemon on loopback, the real scan runner and scanners, the real
 * dispatcher, ingestion and backlog on the real database. Only the containers are replaced — each
 * answers as its tool would, and gitleaks leaves the report this test chooses where it would.
 *
 * <p><b>The defect this pins resolved the backlog.</b> A report that was not JSON, not an array, or not
 * there at all was read as "analysed, no secrets": the secret type was declared examined and every
 * secret issue of the repository was resolved, triage included — with no exception and no log line, and
 * a dashboard that looked better afterwards. Unit tests of the reading cannot see that the absent result
 * reaches ingestion as absent; this follows it to the issue's row.
 *
 * <p>The IaC checker answers cleanly, so the scan completes and is ingested: a scan where nothing ran
 * fails and is never ingested, which would leave the issue open for the wrong reason.
 */
@DisplayName("a secrets report gitleaks did not write, through the built-in worker: the secret's issue stays open")
class SecretsReportFateTest extends VectispireContextTest {

    private static final String FOUND = """
            [{"RuleID": "aws-access-token", "Description": "AWS", "File": "/repo/source/config.py",
              "StartLine": 1, "Fingerprint": "config.py:aws-access-token:1"}]""";

    /** What checkov 3.3.9 prints over a tree with nothing to check (measured). */
    private static final String NOTHING_TO_CHECK = """
            {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0,
             "checkov_version": "3.3.9"}""";

    @MockitoBean
    private ScanRunner runner;

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    /** The report gitleaks leaves at the next run; null leaves none. */
    private final AtomicReference<String> report = new AtomicReference<>();

    private Path tree;
    private Path rules;
    private Repository served;
    private Daemon daemon;

    @BeforeEach
    void serveAndWire() throws Exception {
        tree = Files.createTempDirectory("secrets-fate-tree");
        try (Git git = Git.init().setDirectory(tree.toFile()).setInitialBranch("main").call()) {
            Files.writeString(tree.resolve("config.py"), "key = 'not a secret, the scanner is replaced'\n");
            git.add().addFilepattern(".").call();
            git.commit().setMessage("one file").setSign(false).call();
            served = git.getRepository();
        }
        daemon = new Daemon(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        daemon.setRepositoryResolver((request, name) -> {
            served.incrementOpen();
            return served;
        });
        daemon.start();

        ContainerRunner containers = mock(ContainerRunner.class);
        when(containers.run(any())).thenAnswer(call -> answer(call.getArgument(0)));
        // A mock's ceiling is zero, and the report is now read only within the runner's.
        when(containers.outputBytes()).thenReturn(com.asmolabs.vectispire.common.scanning.ScannerLimits.DEFAULT_OUTPUT_BYTES);
        rules = Files.createTempDirectory("secrets-fate-rules");
        ScanRunner real = new ScanRunner(containers, ScannerImages.PINNED, rules, hash -> List.of(),
                new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE, java.time.Clock.systemUTC());
        when(runner.run(any())).thenAnswer(call -> real.run(call.getArgument(0, ScanTask.class)));

        // A scan another test left waiting would be claimed in place of this one.
        scans.findAll().stream()
                .filter(scan -> ScanStatus.PENDING.wireName().equals(scan.getStatus()))
                .forEach(scan -> {
                    scan.setStatus(ScanStatus.FAILED.wireName());
                    scans.save(scan);
                });
    }

    @AfterEach
    void stop() throws IOException {
        daemon.stop();
        served.close();
        for (Path root : List.of(tree, rules)) {
            try (var paths = Files.walk(root)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
            }
        }
    }

    /** Each scanner as its tool answers; anything but gitleaks and checkov fails, which resolves nothing. */
    private ContainerResult answer(ContainerRun run) throws IOException {
        if (run.image().equals(ScannerImages.PINNED.gitleaks())) {
            String left = report.get();
            if (left != null) {
                Files.writeString(Path.of(run.mounts().getFirst().source()).resolve("vectispire-gitleaks-report.json"), left);
            }
            return new ContainerResult("", "", 0);
        }
        if (run.image().equals(ScannerImages.PINNED.checkov())) {
            return new ContainerResult(NOTHING_TO_CHECK, "", 0);
        }
        return new ContainerResult("", "not in this test", 1);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"not json", "not an array", "elements not objects", "truncated", "no report"})
    @DisplayName("the secret's issue is not resolved, and the scan says the secrets step failed")
    void theIssueStaysOpen(String corruption) {
        long repositoryId = repository();
        report.set(FOUND);
        long first = scanned(repositoryId);
        assertThat(secretIssues(repositoryId)).singleElement()
                .satisfies(issue -> assertThat(issue.getState()).isEqualTo("open"));

        report.set(switch (corruption) {
            case "not json" -> "this is not json";
            case "not an array" -> "{\"RuleID\": \"aws-access-token\", \"File\": \"/repo/source/config.py\"}";
            case "elements not objects" -> "[1, \"text\", null]";
            case "truncated" -> FOUND.substring(0, FOUND.length() / 2);
            case "no report" -> null;
            default -> throw new IllegalArgumentException(corruption);
        });
        long second = scanned(repositoryId);

        ScanEntity scan = scans.findById(second).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        assertThat(scan.getExaminedTypes()).as("the secret type was not examined").doesNotContain("secret");
        assertThat(scan.getError()).contains("secrets");
        assertThat(secretIssues(repositoryId)).singleElement().satisfies(issue -> assertThat(issue.getState())
                .as("resolved on the strength of a report gitleaks did not write").isEqualTo("open"));
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    @DisplayName("the empty array gitleaks writes on a clean tree does resolve it: the test can see a resolution")
    void aCleanReportResolves() {
        long repositoryId = repository();
        report.set(FOUND);
        scanned(repositoryId);

        report.set("[]\n");
        scanned(repositoryId);

        assertThat(secretIssues(repositoryId)).singleElement()
                .satisfies(issue -> assertThat(issue.getState()).isEqualTo("resolved"));
    }

    private List<IssueEntity> secretIssues(long repositoryId) {
        return issues.findAll().stream()
                .filter(issue -> Long.valueOf(repositoryId).equals(issue.getRepoId()))
                .filter(issue -> "secret".equals(issue.getType()))
                .toList();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("git://127.0.0.1:" + daemon.getAddress().getPort() + "/fate-" + UUID.randomUUID() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    /** Queues a scan of the repository, has the built-in worker run it, and answers its id. */
    private long scanned(long repositoryId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        long scanId = scans.save(scan).getId();

        ScanDispatcher.Dispatched round = dispatcher.dispatch("built-in-secrets-fate", 1, List.of());

        assertThat(round.completed()).as("the scan completed: %s", scans.findById(scanId).orElseThrow().getError())
                .isEqualTo(1);
        return scanId;
    }
}
