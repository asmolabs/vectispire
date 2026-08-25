package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
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
 * The debt report's aggregates, against a real engine.
 *
 * <p><b>Why this one is in the campaign when the service was judged not to need it.</b> It did
 * not: it used specifications, and a specification is built by Hibernate for whichever dialect is
 * configured. That changed when the report stopped loading the backlog into memory. What replaced
 * the Java counting is hand-built criteria aggregation — {@code count(distinct coalesce(…))},
 * {@code sum(case when … end)}, {@code min} over a version string, and a {@code select distinct}
 * over an expression — and those are precisely the constructs whose result <em>type</em> is the
 * driver's business rather than Hibernate's. A mapped attribute comes back normalised; the value
 * of {@code sum(case …)} comes back as whatever the driver felt like, which is why
 * {@code IssueAggregatesImpl} reads it as a {@link Number}.
 *
 * <p>So the assertions here are deliberately shallow on arithmetic and specific about SQL:
 * {@code SecurityDebtDatabaseTest} owns the numbers, on one engine, in the ordinary suite. This
 * asks a different question — does the statement parse, and does the row it returns read back as
 * the count it is?
 *
 * <p>The service is exercised rather than the fragment, because the cast lives in between.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the security debt aggregates")
class SecurityDebtIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private SecurityDebtService debt;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    private long alpha;
    private long beta;

    @BeforeEach
    void seed() {
        issues.deleteAll();
        repositories.deleteAll();

        alpha = repository("ssh://git@example.com/team/alpha.git", "alpha");
        beta = repository("ssh://git@example.com/team/beta.git", "beta");

        // One CVE on two repositories: the `count(distinct …)` has to collapse it, and an engine
        // that ignored `distinct` would report two fixes' worth of leverage for one upgrade.
        vulnerability(alpha, "fp-a1", "CVE-2023-0001", Severity.CRITICAL, "spring-core", "5.3.0");
        vulnerability(beta, "fp-b1", "CVE-2023-0001", Severity.CRITICAL, "spring-core", "5.3.9");
        vulnerability(alpha, "fp-a2", "CVE-2023-0002", Severity.HIGH, "spring-core", "5.3.0");

        // No identifier at all: `count(distinct …)` skips nulls on every engine, so the coalesce
        // is what keeps this package on the list rather than silently at zero.
        vulnerability(alpha, "fp-a3", null, Severity.MEDIUM, "left-pad", "1.0.0");

        // A blank package name, which the trim predicate must exclude on every engine — a
        // recommended upgrade of "   " is worse than a missing one.
        vulnerability(alpha, "fp-a4", "CVE-2023-0005", Severity.LOW, "   ", "9");

        issue(alpha, "fp-s1", "generic-api-key", FindingType.SECRET, Severity.HIGH);
        issue(beta, "fp-i1", "AVD-AWS-0088", FindingType.IAC, Severity.LOW);
    }

    @Test
    @DisplayName("the grouped tally parses, and its counts read back as counts")
    void theTallyParses() {
        SecurityDebtReport report = debt.calculateDebt(null, null, Visibility.everything());

        // Reaching this line is half the assertion: a statement the driver refuses, or a count
        // the service cannot read, fails before any number is compared.
        assertThat(report.totalOpenIssues()).isEqualTo(7);
        assertThat(report.criticalIssues()).isEqualTo(2);
        assertThat(report.highIssues()).isEqualTo(2);
        assertThat(report.mediumIssues()).isEqualTo(1);
        assertThat(report.lowIssues()).isEqualTo(2);

        // Five vulnerabilities — 1.5h for the three severe, 0.8h for the other two — plus a
        // secret at 2.0 and an IaC finding at 1.0.
        assertThat(report.vulnerabilitiesDebtHours()).isEqualTo(6.1);
        assertThat(report.totalEstimatedHours()).isEqualTo(9.1);
    }

    @Test
    @DisplayName("distinct identifiers, the case-sum and the version pick, all on the server")
    void thePackageWeightsParse() {
        List<HighImpactFix> fixes = debt.highImpactFixes(null, null, Visibility.everything());

        assertThat(fixes).extracting(HighImpactFix::packageName)
                .as("a blank package name is not an upgrade candidate on any engine")
                .containsExactlyInAnyOrder("spring-core", "left-pad");

        HighImpactFix spring = fixes.stream()
                .filter(fix -> "spring-core".equals(fix.packageName()))
                .findFirst()
                .orElseThrow();

        assertThat(spring.cveCountResolved())
                .as("three findings, two distinct CVEs — the same one twice is one upgrade")
                .isEqualTo(2);
        assertThat(spring.criticalCveCount())
                .as("sum(case when …) is the expression whose type differs by driver")
                .isEqualTo(2);
        assertThat(spring.highCveCount()).isEqualTo(1);
        assertThat(spring.currentVersion())
                .as("the smallest version present, so two runs on one database agree")
                .isEqualTo("5.3.0");
        assertThat(spring.affectedTargetNames()).containsExactlyInAnyOrder("alpha", "beta");

        HighImpactFix leftPad = fixes.stream()
                .filter(fix -> "left-pad".equals(fix.packageName()))
                .findFirst()
                .orElseThrow();
        assertThat(leftPad.cveCountResolved())
                .as("an unnamed finding is one unnamed CVE, not zero — the coalesce, on the server")
                .isEqualTo(1);
        assertThat(leftPad.affectedCves()).containsExactly("UNKNOWN-CVE");
    }

    @Test
    @DisplayName("the visibility predicate survives the grouping")
    void restrictedReadersStayRestricted() {
        // The one failure mode worth a container: an authorization predicate that a `group by`
        // silently drops would widen every restricted reader's report, and it would read as a
        // richer dashboard rather than as a leak.
        SecurityDebtReport report = debt.calculateDebt(
                null, null, Visibility.only(List.of(new ScanTarget.Repository(beta))));

        assertThat(report.totalOpenIssues()).isEqualTo(2);
        assertThat(report.topHighImpactFixes()).singleElement()
                .satisfies(fix -> assertThat(fix.affectedTargetNames()).containsExactly("beta"));
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void vulnerability(
            long repoId, String fingerprint, String identifier, Severity severity,
            String packageName, String packageVersion) {

        IssueEntity entity = build(repoId, fingerprint, identifier, FindingType.VULNERABILITY, severity);
        entity.setPackageName(packageName);
        entity.setPackageVersion(packageVersion);
        issues.save(entity);
    }

    private void issue(long repoId, String fingerprint, String identifier, FindingType type, Severity severity) {
        issues.save(build(repoId, fingerprint, identifier, type, severity));
    }

    private static IssueEntity build(
            long repoId, String fingerprint, String identifier, FindingType type, Severity severity) {

        IssueEntity entity = new IssueEntity();
        entity.setRepoId(repoId);
        entity.setFingerprint(fingerprint);
        entity.setIdentifier(identifier);
        entity.setType(type.wireName());
        entity.setSeverity(severity.wireName());
        entity.setState(IssueState.OPEN.wireName());
        entity.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        entity.setIsKev(false);
        entity.setFirstSeenAt(Instant.now());
        entity.setLastSeenAt(Instant.now());
        entity.setTimesSeen(1);
        return entity;
    }
}
