package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.inventory.ApiInventoryService;
import com.asmolabs.vectispire.core.issues.IssueQueryService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.posture.AttackPathService;
import com.asmolabs.vectispire.core.posture.DashboardQueryService;
import com.asmolabs.vectispire.core.posture.QualityQueryService;
import com.asmolabs.vectispire.core.posture.SecurityDebtService;
import com.asmolabs.vectispire.core.posture.SecurityScorecardService;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.PackageImpact;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.threatintel.EpssPrioritizationService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.LongStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * Every read narrowed by a reader's allowance, for a reader who may see more targets than one statement
 * can bind.
 *
 * <p>A reader's visibility is a set of targets resolved in Java — the account's grants, its teams' and
 * its projects' repositories, intersected with the credential's restriction — so its size is the
 * estate's. The reads narrowed by it bound one parameter per target, and past 65,535 each failed on
 * PostgreSQL ("PreparedStatement can have at most 65 535 parameters"): the issues list, the home page,
 * the quality overview, the finding graph, the attack paths. Each case here failed so before the reads
 * were rewritten, identifiers written into the statement as literals where one statement pages, ranks
 * or counts, and asked a thousand at a time where a lookup can be split. The reader holds seventy
 * thousand grants, all real rows, so the path runs from the grant table through {@link
 * VisibilityService}, as a request does.
 *
 * <p><b>The limit is PostgreSQL's alone</b>: MySQL's client-side statements accept the bound
 * statements, so on MySQL this checks the rest — statement texts of several
 * hundred kilobytes, {@code or}-ed {@code in} lists over both target columns, and the narrowing itself:
 * the granted repository's and image's rows appear, the hidden repository's never do.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the reads of a reader granted seventy thousand targets, on the engine")
class WideAllowanceIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    /** Seventy thousand repositories no row carries — past the PostgreSQL driver's 65,535. */
    private static final List<Long> NOBODY = LongStream.rangeClosed(9_000_000, 9_070_000).boxed().toList();

    private static final Instant AT = Instant.parse("2026-09-01T10:00:00Z");

    /** The estate, written once for the class: seventy thousand grants per test is minutes on MySQL. */
    private static Estate estate;

    private record Estate(long granted, long grantedImage, long hidden, long grantedScan, UserView reader) {}

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
        estate = null;
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private VisibilityService visibility;

    @Autowired
    private SettingsService settings;

    @Autowired
    private IssueQueryService backlog;

    @Autowired
    private DashboardQueryService dashboard;

    @Autowired
    private SecurityScorecardService scorecards;

    @Autowired
    private QualityQueryService quality;

    @Autowired
    private ScanCatalog scanCatalog;

    @Autowired
    private AttackPathService attackPaths;

    @Autowired
    private ApiInventoryService apiInventory;

    @Autowired
    private EpssPrioritizationService epss;

    @Autowired
    private SecurityDebtService debt;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private FindingRepository findings;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private UserRepository users;

    @Autowired
    private JdbcTemplate jdbc;

    private Visibility allowed;

    @BeforeEach
    void seventyThousandGrants() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        if (estate == null) {
            estate = populate();
        }
        allowed = visibility.of(estate.reader(), Visibility.everything());
        assertThat(allowed.asFilter()).get().satisfies(targets -> assertThat(targets).hasSize(NOBODY.size() + 2));
    }

    @Test
    @DisplayName("the issues list: the granted repository's and image's issues, counted, and not the hidden one")
    void theIssuesList() {
        IssueQueryService.IssuePage page = backlog.page(vulnerabilities(), allowed);

        assertThat(identifiers(page)).containsExactlyInAnyOrder("CVE-GRANTED", "CVE-GRANTED-IMAGE");
        assertThat(page.total()).isEqualTo(2);
    }

    @Test
    @DisplayName("a credential narrowed to the image: the intersection, never the union")
    void narrowedByTheCredential() {
        Visibility narrowed = visibility.of(
                estate.reader(), Visibility.only(List.of(new ScanTarget.Container(estate.grantedImage()))));

        assertThat(identifiers(backlog.page(vulnerabilities(), narrowed))).containsExactly("CVE-GRANTED-IMAGE");
    }

    @Test
    @DisplayName("the home page: the granted repository's scan among the recent ones, its quality issue counted, the ranking narrowed")
    void theHomePage() {
        DashboardQueryService.Overview overview = dashboard.overview(allowed);

        assertThat(overview.recentScans()).extracting(DashboardQueryService.RecentScan::id)
                .containsExactly(estate.grantedScan());
        assertThat(overview.qualityTotal()).isEqualTo(1);

        // The maturity ranking grades through the scorecards' reads — the grading counts with the
        // allowance written into the statement, the completed scans narrowed in Java — and lists
        // the granted targets, the scanned one graded, and never the hidden one, scanned as it is.
        List<PostureTrendAnalytics.TargetMaturityScore> ranking = dashboard.postureAnalytics(30, allowed).targetScoreboard();
        assertThat(ranking).extracting(row -> row.targetKind() + ":" + row.targetId())
                .contains("REPOSITORY:" + estate.granted(), "CONTAINER:" + estate.grantedImage())
                .doesNotContain("REPOSITORY:" + estate.hidden());
        assertThat(ranking).filteredOn(row -> row.targetId() == estate.granted() && "REPOSITORY".equals(row.targetKind()))
                .singleElement()
                .satisfies(row -> assertThat(row.securityScore()).isEqualTo(
                        scorecards.getRepositoryScorecard(estate.granted(), allowed).orElseThrow().score()));
    }

    @Test
    @DisplayName("the quality overview: the granted repository's rule, file and repository, and no other")
    void theQualityOverview() {
        QualityQueryService.Overview overview = quality.overview(allowed);

        assertThat(overview.openCount()).isEqualTo(1);
        assertThat(overview.ruleCount()).isEqualTo(1);
        assertThat(overview.fileCount()).isEqualTo(1);
        assertThat(overview.topRules()).extracting(QualityQueryService.Bucket::label).containsExactly("rule-granted");
        assertThat(overview.topFiles()).extracting(QualityQueryService.Bucket::label).containsExactly("granted.java");
        assertThat(overview.topTargets()).hasSize(1);
    }

    @Test
    @DisplayName("the finding graph and the package impacts: the granted repository's package, not the hidden one's")
    void theFindingGraph() {
        assertThat(scanCatalog.packageImpacts(allowed)).extracting(PackageImpact::packageName)
                .containsExactly("granted-lib");
        assertThat(scanCatalog.findingsForGraph("", false, false, allowed))
                .extracting(row -> row.finding().packageName())
                .containsExactly("granted-lib");
    }

    @Test
    @DisplayName("the attack paths, the attack surface, the EPSS fleet and the debt: every read answers")
    void theEstateReads() {
        assertThat(attackPaths.getOverview(allowed)).isNotNull();
        assertThat(apiInventory.globalAttackSurface(allowed)).isNotNull();
        assertThat(epss.getFleetSummary(allowed)).isNotNull();
        assertThat(debt.calculateDebt(null, null, allowed)).isNotNull();
        assertThat(debt.highImpactFixes(null, null, allowed)).isNotNull();
    }

    private static IssueQueryService.BacklogQuery vulnerabilities() {
        return new IssueQueryService.BacklogQuery(null, null, FindingType.VULNERABILITY.wireName(), null, null,
                null, null, null, false, false, false, false, null, 500, 0);
    }

    private static List<String> identifiers(IssueQueryService.IssuePage page) {
        return page.items().stream().map(entry -> entry.issue().identifier()).toList();
    }

    private Estate populate() {
        long granted = repository();
        long grantedImage = container();
        long hidden = repository();

        issue(granted, null, FindingType.VULNERABILITY, "CVE-GRANTED", "granted-lib", null);
        issue(null, grantedImage, FindingType.VULNERABILITY, "CVE-GRANTED-IMAGE", null, null);
        issue(hidden, null, FindingType.VULNERABILITY, "CVE-HIDDEN", "hidden-lib", null);
        issue(granted, null, FindingType.QUALITY, "rule-granted", null, "granted.java");
        issue(hidden, null, FindingType.QUALITY, "rule-hidden", null, "hidden.java");

        long grantedScan = scan(granted, AT);
        // Newer than the granted one: a narrowing that failed open would put it first.
        long hiddenScan = scan(hidden, AT.plusSeconds(3_600));
        finding(grantedScan, "granted-lib");
        finding(hiddenScan, "hidden-lib");

        UserView reader = reader();
        List<Object[]> grants = new ArrayList<>();
        NOBODY.forEach(id -> grants.add(new Object[] {reader.id(), TeamRules.KIND_REPOSITORY, id}));
        grants.add(new Object[] {reader.id(), TeamRules.KIND_REPOSITORY, granted});
        grants.add(new Object[] {reader.id(), TeamRules.KIND_CONTAINER, grantedImage});
        insertGrants(grants);
        return new Estate(granted, grantedImage, hidden, grantedScan, reader);
    }

    /** A thousand rows per statement: seventy thousand single inserts are minutes on MySQL. */
    private void insertGrants(List<Object[]> grants) {
        for (int from = 0; from < grants.size(); from += 1_000) {
            List<Object[]> chunk = grants.subList(from, Math.min(from + 1_000, grants.size()));
            String values = String.join(", ", Collections.nCopies(chunk.size(), "(?, ?, ?)"));
            jdbc.update("insert into t_user_target (user_id, target_kind, target_id) values " + values,
                    chunk.stream().flatMap(java.util.Arrays::stream).toArray());
        }
    }

    private UserView reader() {
        UserEntity user = new UserEntity();
        user.setUsername("reader-" + System.nanoTime());
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setCreatedAt(AT);
        user.setUpdatedAt(AT);
        return UserView.of(users.save(user));
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/wide-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("example/wide-" + System.nanoTime());
        container.setTag("1.0");
        return containers.save(container).getId();
    }

    private void issue(Long repository, Long container, FindingType type, String identifier, String packageName,
            String filePath) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository);
        issue.setContainerId(container);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier(identifier);
        issue.setPackageName(packageName);
        issue.setFilePath(filePath);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(AT);
        issue.setLastSeenAt(AT);
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long scan(long repository, Instant createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        return scans.save(scan).getId();
    }

    private void finding(long scan, String packageName) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier("CVE-2021-44228");
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setPackageName(packageName);
        finding.setSource("grype");
        finding.setCreatedAt(AT);
        findings.save(finding);
    }
}
