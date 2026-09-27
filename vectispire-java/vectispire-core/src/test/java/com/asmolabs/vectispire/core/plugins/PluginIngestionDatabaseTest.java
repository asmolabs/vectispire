package com.asmolabs.vectispire.core.plugins;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.IssueSyncService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.ObservedFinding;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A plugin's three states, through the real ingestion and the real backlog, against a database: what
 * each does to the issues the plugin opened before — and to nobody else's.
 */
@DisplayName("plugin results folded into the backlog, against a database")
class PluginIngestionDatabaseTest extends VectispireContextTest {

    private static final String DIGEST_V1 = "1".repeat(64);
    private static final String DIGEST_V2 = "2".repeat(64);

    @Autowired
    private ScanIngestor ingestor;

    @Autowired
    private IssueSyncService sync;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private FindingRepository findings;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TransactionTemplate transactions;

    private long repositoryId;

    @BeforeEach
    void repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/plugins-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        repositoryId = repositories.save(repository).getId();
    }

    private ScanEntity scan() {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        return scans.save(scan);
    }

    private ScanIngestor.Reconciliation ingest(PluginStep... steps) {
        ScanArtifacts.Builder artifacts = ScanArtifacts.builder();
        for (PluginStep step : steps) {
            artifacts.plugin(step);
        }
        ScanEntity scan = scan();
        return transactions.execute(status -> ingestor.ingest(scan, artifacts.build(Duration.ofSeconds(1))));
    }

    private static SarifFinding finding(String rule, String file) {
        return new SarifFinding(rule, Severity.HIGH, file, 3, "message for " + rule);
    }

    private static PluginStep.Produced produced(String plugin, String digest, String version, SarifFinding... found) {
        return new PluginStep.Produced(plugin, digest, "the tool", version, List.of(found));
    }

    private List<IssueEntity> open(String tool) {
        return issues.findAll().stream()
                .filter(issue -> tool.equals(issue.getTool()))
                .filter(issue -> IssueState.OPEN.wireName().equals(issue.getState()))
                .toList();
    }

    @Test
    @DisplayName("produced opens the plugin's issues, typed and keyed by the plugin, and writes the scan's findings")
    void produced() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py"), finding("ACME002", "src/b.py")));

        assertThat(open("plugin:acme-lint")).hasSize(2).allSatisfy(issue -> {
            assertThat(issue.getType()).isEqualTo(FindingType.PLUGIN.wireName());
            assertThat(issue.getSource()).isEqualTo("acme-lint");
            assertThat(issue.getToolName()).isEqualTo("the tool");
            assertThat(issue.getToolVersion()).isEqualTo("1.0");
            assertThat(issue.getImportSource()).isNull();
        });
        assertThat(findings.findAll()).extracting(finding -> finding.getTool()).containsOnly("plugin:acme-lint");
    }

    @Test
    @DisplayName("an empty report resolves that plugin's issues, and only that plugin's")
    void producedEmptyResolvesItsOwn() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")),
                produced("other", DIGEST_V1, "1.0", finding("OTHER1", "src/a.py")));

        ScanIngestor.Reconciliation result = ingest(produced("acme-lint", DIGEST_V1, "1.0"),
                produced("other", DIGEST_V1, "1.0", finding("OTHER1", "src/a.py")));

        assertThat(result.resolved()).isEqualTo(1);
        assertThat(open("plugin:acme-lint")).isEmpty();
        assertThat(open("plugin:other")).hasSize(1);
    }

    @Test
    @DisplayName("not applicable leaves the plugin's issues as they are, and so does absent")
    void notApplicableAndAbsentResolveNothing() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")),
                produced("flaky", DIGEST_V1, "1.0", finding("FLAKY1", "src/b.py")));

        ScanIngestor.Reconciliation result = ingest(
                new PluginStep.NotApplicable("acme-lint", DIGEST_V1, Set.of(Language.PYTHON)),
                new PluginStep.Absent("flaky", DIGEST_V1, "exited with 2"));

        assertThat(result.resolved()).isZero();
        assertThat(open("plugin:acme-lint")).hasSize(1);
        assertThat(open("plugin:flaky")).hasSize(1);
    }

    @Test
    @DisplayName("a new image version keeps every issue's identity, and with it the triage")
    void versionsKeepTheTriage() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")));
        IssueEntity triaged = open("plugin:acme-lint").getFirst();
        triaged.setTriageStatus(TriageStatus.NOT_AFFECTED.wireName());
        triaged.setTriageJustification("code_not_reachable");
        issues.save(triaged);

        ScanIngestor.Reconciliation result = ingest(produced("acme-lint", DIGEST_V2, "2.0", finding("ACME001", "src/a.py")));

        assertThat(result.created()).isZero();
        assertThat(result.resolved()).isZero();
        assertThat(open("plugin:acme-lint")).singleElement().satisfies(issue -> {
            assertThat(issue.getId()).isEqualTo(triaged.getId());
            assertThat(issue.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
            assertThat(issue.getToolVersion()).isEqualTo("2.0");
            assertThat(issue.getTimesSeen()).isEqualTo(2);
        });
    }

    @Test
    @DisplayName("renaming the plugin is a new identity: its old issues resolve only when the old id reports clean")
    void renamingIsANewIdentity() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")));

        ingest(produced("acme-lint-2", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")));

        assertThat(open("plugin:acme-lint")).hasSize(1);
        assertThat(open("plugin:acme-lint-2")).hasSize(1);
    }

    @Test
    @DisplayName("an import and a plugin never touch each other's issues, even for the same rule and file")
    void importsAndPluginsAreSeparate() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")));
        ObservedFinding imported = new ObservedFinding("imported", "acme-lint", "ACME001", "high", null, null, null,
                "src/a.py", 3, null, null, null, null, null, null, null, null, false, "from CI",
                "import:ci/acme-lint", "acme-lint", "1.0");

        transactions.executeWithoutResult(status -> sync.syncImport(
                new ScanTarget.Repository(repositoryId), "ci", Set.of("import:ci/acme-lint"), List.of(imported)));
        transactions.executeWithoutResult(status -> sync.syncImport(
                new ScanTarget.Repository(repositoryId), "ci", Set.of("import:ci/acme-lint"), List.of()));

        assertThat(open("import:ci/acme-lint")).isEmpty();
        assertThat(open("plugin:acme-lint")).as("an empty import resolves its own tool, not the plugin").hasSize(1);

        ingest(produced("acme-lint", DIGEST_V1, "1.0"));
        assertThat(issues.findAll()).filteredOn(issue -> "import:ci/acme-lint".equals(issue.getTool()))
                .allSatisfy(issue -> assertThat(issue.getImportSource()).isEqualTo("ci"));
    }

    @Test
    @DisplayName("a caller that names the plugin type as scanned resolves nothing by type — only a tool resolves its own")
    void neverByType() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")),
                produced("other", DIGEST_V1, "1.0", finding("OTHER1", "src/a.py")));
        ScanEntity scan = scan();

        IssueSyncService.SyncResult result = transactions.execute(status -> sync.sync(scan.getId(),
                new ScanTarget.Repository(repositoryId), List.of(), Set.of(FindingType.PLUGIN, FindingType.IMPORTED),
                java.util.Map.of(), null));

        assertThat(result.resolved()).isZero();
        assertThat(open("plugin:acme-lint")).hasSize(1);
        assertThat(open("plugin:other")).hasSize(1);
    }

    @Test
    @DisplayName("a scan that ran every scanner and no plugin resolves no plugin's issues")
    void scannersDoNotResolvePlugins() {
        ingest(produced("acme-lint", DIGEST_V1, "1.0", finding("ACME001", "src/a.py")));

        ScanEntity scan = scan();
        transactions.execute(status -> ingestor.ingest(scan, ScanArtifacts.builder()
                .sast(List.of()).secrets(List.of()).iac(List.of()).dependencies(List.of())
                .build(Duration.ofSeconds(1))));

        assertThat(open("plugin:acme-lint")).hasSize(1);
    }
}
