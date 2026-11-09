package com.asmolabs.vectispire.core.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.inventory.ComponentCatalog;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.plugins.ReportImportCatalog;
import com.asmolabs.vectispire.core.plugins.SarifImportView;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.ExaminingScanRow;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.LongStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The owners' questions a checklist's measurement asks (decision 0032 §6), on a real engine, each
 * asked for seventy thousand repositories or scans — a project's repositories are sized by the data.
 *
 * <p>PostgreSQL is the engine that refuses an unbatched statement here ("at most 65 535 parameters");
 * MySQL's client-side statements accept one, so a green run on MySQL alone says nothing of the
 * batching. What MySQL checks is the rest: a {@code case} in a
 * constructor expression, {@code like … escape '!'} over a long-text column, {@code concat} with a null,
 * a {@code sum} over a {@code case}, the group by over a {@code not in} — each an engine's own spelling.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the measurements' questions on the engine")
class MeasurementQueriesIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant SINCE = Instant.parse("2026-09-01T00:00:00Z");

    /** Seventy thousand identifiers no row carries — past the PostgreSQL driver's 65,535. */
    private static final List<Long> NOBODY = LongStream.rangeClosed(5_000_000, 5_070_000).boxed().toList();

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

    @Autowired
    private ScanCatalog scanCatalog;

    @Autowired
    private IssueCatalog issueCatalog;

    @Autowired
    private ReportImportCatalog importCatalog;

    @Autowired
    private ComponentCatalog componentCatalog;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private SarifImportRepository sarif;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TargetNaming naming;

    @BeforeEach
    void empty() {
        components.deleteAll();
        issues.deleteAll();
        sarif.deleteAll();
        scans.deleteAll();
        repositories.deleteAll();
    }

    @Test
    @DisplayName("the scans: whether the newest analysed one kept its SBOM, those within the age, the unrecorded among them")
    void scans() {
        long kept = repository("kept");
        long purged = repository("purged");
        scan(kept, "vulnerability", SINCE.plus(Duration.ofDays(1)), true, null);
        scan(purged, "vulnerability", SINCE.plus(Duration.ofDays(1)), false, null);
        scan(purged, null, SINCE.plus(Duration.ofDays(2)), true, null);
        scan(purged, null, SINCE.minus(Duration.ofDays(2)), true, null);

        Map<Long, ExaminingScanRow> newest = scanCatalog.newestExamining(ids(kept, purged), FindingType.VULNERABILITY,
                Instant.EPOCH);
        assertThat(newest.get(kept).sbomStored()).isTrue();
        assertThat(newest.get(purged).sbomStored()).as("a null payload, read without loading one").isFalse();

        Map<Long, ScanCatalog.ScansWithin> within = scanCatalog.completedWithin(ids(kept, purged), SINCE);
        assertThat(within).containsOnlyKeys(kept, purged);
        assertThat(within.get(purged).completed()).as("the one before the age is not counted").isEqualTo(2);
        assertThat(within.get(purged).unrecorded()).isEqualTo(1);
        assertThat(within.get(kept).unrecorded()).isZero();
    }

    @Test
    @DisplayName("the plugins: each one's state per scan within the age, by its whole id, and whether one before names it")
    void plugins() {
        long repository = repository("plugged");
        long other = repository("other");
        scan(repository, "sast", SINCE.plus(Duration.ofDays(1)), true, steps("java-arch", "produced"));
        scan(repository, "sast", SINCE.plus(Duration.ofDays(2)), true, steps("java-arch", "not_applicable"));
        // A longer id holding this one is another plugin.
        scan(other, "sast", SINCE.plus(Duration.ofDays(1)), true, steps("java-arch-extra", "produced"));
        scan(other, "sast", SINCE.minus(Duration.ofDays(3)), true, steps("java-arch", "absent"));

        Map<Long, List<ScanCatalog.PluginRun>> runs = scanCatalog.pluginRunsWithin(ids(repository, other), "java-arch",
                SINCE);
        assertThat(runs).containsOnlyKeys(repository);
        assertThat(runs.get(repository)).extracting(run -> run.outcome().state())
                .as("newest first").containsExactly("not_applicable", "produced");
        assertThat(scanCatalog.namingPluginBefore(ids(repository, other), "java-arch", SINCE)).containsOnly(other);
    }

    @Test
    @DisplayName("the backlog: a scope's issues per severity and state, settled triage out, a status this version does not know in")
    void theBacklog() {
        long repository = repository("backlog");
        issue(repository, "secret", null, "critical", "open", "under_review");
        issue(repository, "secret", null, "critical", "open", "not_affected");
        issue(repository, "secret", null, "critical", "resolved", "fixed");
        issue(repository, "secret", null, "high", "open", "escalated_to_vendor");
        issue(repository, "secret", null, "high", "resolved", "affected");
        issue(repository, "plugin", "plugin:java-arch", "high", "open", "under_review");
        issue(repository, "plugin", "plugin:java-archive", "high", "open", "under_review");

        List<IssueCatalog.ScopeCount> secrets = issueCatalog.countUnsettledOfTypeWithin("secret", ids(repository));
        assertThat(secrets).extracting(count -> count.severity() + "/" + count.state() + "=" + count.count())
                .containsExactlyInAnyOrder("critical/open=1", "high/open=1", "high/resolved=1");
        assertThat(issueCatalog.countUnsettledOfToolWithin("plugin:java-arch", ids(repository)))
                .as("a tool's key, whole").singleElement().satisfies(count -> assertThat(count.count()).isEqualTo(1));
    }

    @Test
    @DisplayName("the imports: the newest carrying a tool, its key escaped, and those from before the record")
    void theImports() {
        long repository = repository("imported");
        long other = repository("other");
        sarifImport(repository, "import:ledger-ci/sonar_scanner", SINCE.plus(Duration.ofDays(1)));
        long newest = sarifImport(repository, "import:ledger-ci/eslint,import:ledger-ci/sonar_scanner",
                SINCE.plus(Duration.ofDays(2)));
        // An underscore is a wildcard to `like` unless escaped: this key must not answer for sonar_scanner.
        sarifImport(other, "import:ledger-ci/sonarXscanner", SINCE.plus(Duration.ofDays(1)));
        sarifImport(other, null, SINCE.plus(Duration.ofDays(1)));

        Map<Long, SarifImportView> carrying = importCatalog.newestCarrying(ids(repository, other),
                "import:ledger-ci/sonar_scanner");
        assertThat(carrying).containsOnlyKeys(repository);
        assertThat(carrying.get(repository).id()).isEqualTo(newest);
        assertThat(importCatalog.newestCarrying(ids(repository, other), "import:ledger-ci/eslint")).containsOnlyKeys(
                repository);
        assertThat(importCatalog.unrecordedSince(ids(repository, other), "ledger-ci", SINCE)).containsOnly(other);
        assertThat(importCatalog.unrecordedSince(ids(repository, other), "ledger-ci",
                SINCE.plus(Duration.ofDays(5)))).isEmpty();
    }

    @Test
    @DisplayName("the inventory: the components of seventy thousand scans' worth of identifiers, per scan")
    void theInventory() {
        long repository = repository("inventoried");
        long scanned = scan(repository, "vulnerability", SINCE.plus(Duration.ofDays(1)), true, null);
        component(scanned, "ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1");
        component(scanned, "left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");

        List<Long> scanIds = new ArrayList<>(NOBODY);
        scanIds.add(scanned);
        Map<Long, List<ComponentCatalog.Component>> listed = componentCatalog.componentsOf(scanIds);
        assertThat(listed).containsOnlyKeys(scanned);
        assertThat(listed.get(scanned)).extracting(ComponentCatalog.Component::purl)
                .containsExactlyInAnyOrder("pkg:maven/com.example/ledger-core@3.2.1", "pkg:npm/left-pad@1.3.0");
    }

    @Test
    @DisplayName("the names the evidence carries: seventy thousand repositories' worth of identifiers, those that exist named")
    void theRepositoriesNames() {
        long named = repository("checkout-api");
        long other = repository("checkout-web");
        Map<Long, String> names = naming.repositoryNames(ids(named, other));
        assertThat(names).containsOnlyKeys(named, other);
        assertThat(names.get(named)).isEqualTo(TargetNaming.of(repositories.findById(named).orElseThrow()));
    }

    /** The real identifiers among seventy thousand no row carries, first and last. */
    private static List<Long> ids(Long... real) {
        List<Long> ids = new ArrayList<>();
        ids.add(real[0]);
        ids.addAll(NOBODY);
        ids.addAll(List.of(real).subList(1, real.length));
        return ids;
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repositoryId, String examinedTypes, Instant createdAt, boolean sbom, String pluginSteps) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        scan.setAttempts(1);
        scan.setExaminedTypes(examinedTypes);
        scan.setSbom(sbom ? "{\"artifacts\":[]}" : null);
        scan.setPluginSteps(pluginSteps);
        return scans.save(scan).getId();
    }

    private static String steps(String pluginId, String state) {
        return "[{\"pluginId\":\"" + pluginId + "\",\"manifestDigest\":\"sha256:" + "a".repeat(64) + "\",\"state\":\""
                + state + "\",\"findings\":null,\"languages\":[],\"reason\":null}]";
    }

    private void issue(long repositoryId, String type, String tool, String severity, String state, String triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint(UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", ""));
        issue.setType(type);
        issue.setTool(tool);
        issue.setSeverity(severity);
        issue.setState(state);
        issue.setTriageStatus(triage);
        issue.setFirstSeenAt(SINCE);
        issue.setLastSeenAt(SINCE);
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long sarifImport(long repositoryId, String toolKeys, Instant at) {
        SarifImportEntity row = new SarifImportEntity();
        row.setSourceId(1L);
        row.setSourceSlug("ledger-ci");
        row.setRepoId(repositoryId);
        row.setTools("tools as the document named them");
        row.setToolKeys(toolKeys);
        row.setDocumentSha256("0".repeat(64));
        row.setImportedAt(at);
        row.setImportedBy("pipeline");
        row.setApiKeyId(UUID.randomUUID());
        return sarif.save(row).getId();
    }

    private void component(long scanId, String name, String version, String purl) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfComponent = scans.findById(scanId).orElseThrow();
        component.setRepoId(scanOfComponent.getRepoId());
        component.setContainerId(scanOfComponent.getContainerId());
        component.setScanCreatedAt(scanOfComponent.getCreatedAt());
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        components.save(component);
    }
}
