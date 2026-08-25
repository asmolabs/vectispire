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
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The debt report's arithmetic, pinned to exact numbers.
 *
 * <p><b>Written before the report stopped loading the whole backlog, and that order is the
 * point.</b> {@code calculateDebt} materialised every open issue as a managed entity and both
 * target tables in full, then counted in Java. Replacing that with grouped projections is only
 * safe if something already knows what the old arithmetic answered — and nothing did: the sole
 * coverage was {@code SecurityDebtRoutesTest}, which asserts that the route responds.
 *
 * <p>So every figure below is a <em>characterisation</em>: it records what the service computed
 * on this fixture, not what one might argue it ought to. A change of behaviour has to be a
 * deliberate edit here, visible in a diff, rather than a number that quietly drifted while
 * somebody optimised a query.
 *
 * <p><b>One of those recorded figures is a defect, and it is recorded rather than fixed.</b> See
 * {@link #onlyFourOfEightTypesCostAnything()}: half the finding types contribute no hours at all,
 * so the totals disagree with the issue count on the same screen. Correcting it would change
 * every estimate the product has ever shown, which is a decision and not a refactor.
 */
@DisplayName("the security debt report, against a database")
class SecurityDebtDatabaseTest extends VectispireContextTest {

    /** Hibernate counts nothing unless asked, and the assertion below is a count. */
    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private SecurityDebtService debt;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Issues issues;

    private long alpha;
    private long beta;
    private long image;

    @BeforeEach
    void seed() {
        alpha = repository("ssh://git@example.com/team/alpha.git", "alpha");
        beta = repository("ssh://git@example.com/team/beta.git", "beta");
        image = container("registry.example.com", "team/service", "1.4.0");

        // One package across two repositories, so the CVE set has to deduplicate an identifier
        // seen twice while the target list keeps both names.
        vulnerability(alpha, null, "fp-a1", "CVE-2023-0001", Severity.CRITICAL, "spring-core", "5.3.0");
        vulnerability(alpha, null, "fp-a2", "CVE-2023-0002", Severity.HIGH, "spring-core", "5.3.0");
        vulnerability(alpha, null, "fp-a3", "CVE-2023-0003", Severity.MEDIUM, "spring-core", "5.3.0");
        vulnerability(beta, null, "fp-b1", "CVE-2023-0001", Severity.CRITICAL, "spring-core", "5.3.0");

        // A container target: the second of the two nullable keys, and the one a repository-only
        // fixture never exercises.
        vulnerability(null, image, "fp-c1", "CVE-2024-0009", Severity.HIGH, "openssl", "1.1.1");

        // A vulnerability with no package: it costs hours but can never be a high-impact fix,
        // which is the distinction between the two halves of the report.
        vulnerability(alpha, null, "fp-a4", "CVE-2023-0004", Severity.HIGH, null, null);

        // The three other types that cost something, one each.
        issue(alpha, null, "fp-s1", "generic-api-key", FindingType.SECRET, Severity.HIGH, IssueState.OPEN);
        issue(alpha, null, "fp-q1", "java.lang.unused", FindingType.QUALITY, Severity.MEDIUM, IssueState.OPEN);
        issue(beta, null, "fp-i1", "AVD-AWS-0088", FindingType.IAC, Severity.LOW, IssueState.OPEN);

        // Resolved, so it belongs nowhere. Dropping the state filter is a plausible slip and the
        // counts are the only place it would show.
        issue(alpha, null, "fp-a9", "CVE-2020-9999", FindingType.VULNERABILITY, Severity.CRITICAL,
                IssueState.RESOLVED);
    }

    @Test
    @DisplayName("the counts and the hours, on the whole estate")
    void theWholeEstate() {
        SecurityDebtReport report = debt.calculateDebt(null, null, Visibility.everything());

        assertThat(report.totalOpenIssues()).isEqualTo(9);
        assertThat(report.criticalIssues()).isEqualTo(2);
        assertThat(report.highIssues()).isEqualTo(4);
        assertThat(report.mediumIssues()).isEqualTo(2);
        assertThat(report.lowIssues()).isEqualTo(1);

        // Six vulnerabilities: 1.5h each for critical and high, 0.8h below that.
        assertThat(report.vulnerabilitiesDebtHours()).isEqualTo(8.3);
        assertThat(report.secretsDebtHours()).isEqualTo(2.0);
        assertThat(report.sastDebtHours()).isEqualTo(2.5);
        assertThat(report.iacDebtHours()).isEqualTo(1.0);

        assertThat(report.totalEstimatedHours()).isEqualTo(13.8);
        assertThat(report.totalEstimatedPersonDays()).isEqualTo(1.7);
    }

    @Test
    @DisplayName("half the finding types cost nothing, which is a defect this test records")
    void onlyFourOfEightTypesCostAnything() {
        // `sastDebtHours` is fed by QUALITY. The type actually called SAST — what the ingestor
        // files a security-category Semgrep result under — is not in the effort switch at all,
        // and neither are LICENSE, EOL and AI_REVIEW. Being a switch *statement* rather than an
        // expression, the compiler never asked about them.
        issue(alpha, null, "fp-x1", "java.lang.security.audit", FindingType.SAST, Severity.CRITICAL,
                IssueState.OPEN);
        issue(alpha, null, "fp-x2", "GPL-3.0", FindingType.LICENSE, Severity.HIGH, IssueState.OPEN);
        issue(alpha, null, "fp-x3", "node-18", FindingType.EOL, Severity.HIGH, IssueState.OPEN);

        SecurityDebtReport report = debt.calculateDebt(null, null, Visibility.everything());

        // Counted as open, and counted as severe...
        assertThat(report.totalOpenIssues()).isEqualTo(12);
        assertThat(report.criticalIssues()).isEqualTo(3);

        // ...but free to fix, according to the same report. Three findings, one of them critical,
        // added no hours to any bucket and none to the total.
        assertThat(report.totalEstimatedHours())
                .as("recording the gap, not endorsing it: a critical SAST finding costs nothing")
                .isEqualTo(13.8);
    }

    @Test
    @DisplayName("the high-impact fixes, their leverage and their order")
    void theFixes() {
        List<HighImpactFix> fixes = debt.calculateDebt(null, null, Visibility.everything())
                .topHighImpactFixes();

        assertThat(fixes).hasSize(2);

        HighImpactFix spring = fixes.get(0);
        assertThat(spring.packageName()).isEqualTo("spring-core");
        assertThat(spring.currentVersion()).isEqualTo("5.3.0");
        assertThat(spring.recommendedVersion()).isEqualTo("latest-patch");
        assertThat(spring.cveCountResolved())
                .as("four issues, three distinct identifiers: the same CVE on two repositories is one fix")
                .isEqualTo(3);
        assertThat(spring.criticalCveCount()).isEqualTo(2);
        assertThat(spring.highCveCount()).isEqualTo(1);
        assertThat(spring.estimatedHours()).isEqualTo(1.3);
        assertThat(spring.leverageScore()).isEqualTo(10.4);
        assertThat(spring.affectedCves())
                .containsExactlyInAnyOrder("CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003");
        assertThat(spring.affectedTargetNames()).containsExactlyInAnyOrder("alpha", "beta");

        HighImpactFix openssl = fixes.get(1);
        assertThat(openssl.packageName()).isEqualTo("openssl");
        assertThat(openssl.estimatedHours()).isEqualTo(1.1);
        assertThat(openssl.leverageScore()).isEqualTo(3.2);
        assertThat(openssl.affectedTargetNames())
                .as("a container is named by image and tag, not by a repository name")
                .containsExactly("team/service:1.4.0");

        assertThat(fixes.get(0).leverageScore())
                .as("most leverage first — the list is a work order")
                .isGreaterThan(fixes.get(1).leverageScore());
    }

    @Test
    @DisplayName("asking for one repository narrows both halves")
    void oneTarget() {
        SecurityDebtReport report = debt.calculateDebt(beta, null, Visibility.everything());

        assertThat(report.totalOpenIssues()).isEqualTo(2);
        assertThat(report.criticalIssues()).isEqualTo(1);
        assertThat(report.iacDebtHours()).isEqualTo(1.0);
        assertThat(report.vulnerabilitiesDebtHours()).isEqualTo(1.5);

        // The package is still spring-core, but only beta's single CVE is on the bill — a fix
        // list scoped to one target that quoted the estate's numbers would be worse than none.
        assertThat(report.topHighImpactFixes()).singleElement()
                .satisfies(fix -> {
                    assertThat(fix.cveCountResolved()).isEqualTo(1);
                    assertThat(fix.affectedTargetNames()).containsExactly("beta");
                });
    }

    @Test
    @DisplayName("a restricted reader is billed only for what they can see")
    void visibilityIsApplied() {
        SecurityDebtReport report = debt.calculateDebt(
                null, null, Visibility.only(List.of(new ScanTarget.Repository(beta))));

        assertThat(report.totalOpenIssues()).isEqualTo(2);
        assertThat(report.topHighImpactFixes()).singleElement()
                .satisfies(fix -> assertThat(fix.affectedTargetNames()).containsExactly("beta"));
    }

    @Test
    @DisplayName("a reader assigned nothing sees an empty report, not the estate's")
    void anEmptyAllowanceIsNotNoFilter() {
        // The inversion `Visibility` exists to prevent, asserted at the level that would show it.
        SecurityDebtReport report = debt.calculateDebt(null, null, Visibility.only(List.of()));

        assertThat(report.totalOpenIssues()).isZero();
        assertThat(report.totalEstimatedHours()).isZero();
        assertThat(report.topHighImpactFixes()).isEmpty();
    }

    @Test
    @DisplayName("no more than ten fixes come back, and they are the ten with most leverage")
    void theListIsCapped() {
        issues.deleteAll();
        // Fifteen packages of increasing weight: the cap has to keep the heavy end, and a cap
        // applied before the sort would keep whichever fifteen the map happened to iterate first.
        for (int index = 1; index <= 15; index++) {
            for (int cve = 0; cve < index; cve++) {
                vulnerability(alpha, null, "fp-p" + index + "-" + cve, "CVE-9000-" + index + "-" + cve,
                        Severity.CRITICAL, "pkg-" + index, "1.0.0");
            }
        }

        List<HighImpactFix> fixes = debt.calculateDebt(null, null, Visibility.everything())
                .topHighImpactFixes();

        assertThat(fixes).hasSize(10);
        assertThat(fixes).extracting(HighImpactFix::packageName).doesNotContain("pkg-1", "pkg-2", "pkg-3");
        assertThat(fixes.getFirst().packageName()).isEqualTo("pkg-15");
        assertThat(fixes).isSortedAccordingTo(
                java.util.Comparator.comparingDouble(HighImpactFix::leverageScore).reversed());
    }

    @Test
    @DisplayName("thirty-three times the backlog loads no more rows into memory")
    void theWorkDoesNotFollowTheBacklog() {
        // **The regression this change exists to prevent, stated as a property — and stated in
        // the right unit.** The first version of this test counted queries and was wrong to: the
        // old code issued three, the new one issues four or five, and it was never the count that
        // hurt. What grew with the backlog was what came *back*: every open issue as a managed
        // entity, thirty-nine columns and a dirty-checking snapshot each, plus both target tables
        // in full for a handful of names.
        //
        // So the assertion is on entities loaded. Aggregates return scalars and load none; the
        // only rows left are the names of the targets the ranked packages touch, and there are at
        // most a few per package.
        int onASmallBacklog = entitiesLoadedBuildingTheReport();

        for (int index = 1; index <= 30; index++) {
            for (int cve = 0; cve < 10; cve++) {
                vulnerability(alpha, null, "fp-big-" + index + "-" + cve, "CVE-9100-" + index + "-" + cve,
                        Severity.HIGH, "bulk-" + index, "2.0.0");
            }
        }
        assertThat(debt.calculateDebt(null, null, Visibility.everything()).totalOpenIssues())
                .as("the fixture really did grow, or the comparison below means nothing")
                .isEqualTo(309);

        assertThat(entitiesLoadedBuildingTheReport())
                .as("three hundred more issues must not put three hundred more rows in memory")
                .isLessThanOrEqualTo(onASmallBacklog);

        // An absolute ceiling as well as a relative one: "no worse than before" would still pass
        // if both ends grew together. Ten targets' names is the most this report can need.
        assertThat(entitiesLoadedBuildingTheReport())
                .as("whatever the estate holds, the report reads a bounded number of rows")
                .isLessThanOrEqualTo(20);
    }

    @Test
    @DisplayName("the fixes endpoint no longer computes the report it throws away")
    void theFixesAreCheaperThanTheReport() {
        // `/high-impact-fixes` called `calculateDebt` and kept its last field, so a page of ten
        // upgrade suggestions tallied the entire backlog by severity first and discarded it.
        Statistics statistics = statistics();

        statistics.clear();
        debt.calculateDebt(null, null, Visibility.everything());
        long forTheWholeReport = statistics.getQueryExecutionCount();

        statistics.clear();
        debt.highImpactFixes(null, null, Visibility.everything());
        long forTheFixesAlone = statistics.getQueryExecutionCount();

        assertThat(forTheFixesAlone)
                .as("asking only for the fixes must cost less than asking for everything")
                .isLessThan(forTheWholeReport);
    }

    private int entitiesLoadedBuildingTheReport() {
        Statistics statistics = statistics();
        statistics.clear();
        debt.calculateDebt(null, null, Visibility.everything());
        return (int) statistics.getEntityLoadCount();
    }

    private Statistics statistics() {
        return entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long container(String registry, String name, String tag) {
        ContainerEntity entity = new ContainerEntity();
        entity.setRegistry(registry);
        entity.setImageName(name);
        entity.setTag(tag);
        return containers.save(entity).getId();
    }

    private void vulnerability(
            Long repoId, Long containerId, String fingerprint, String identifier,
            Severity severity, String packageName, String packageVersion) {

        IssueEntity entity = build(repoId, containerId, fingerprint, identifier,
                FindingType.VULNERABILITY, severity, IssueState.OPEN);
        entity.setPackageName(packageName);
        entity.setPackageVersion(packageVersion);
        issues.save(entity);
    }

    private void issue(
            Long repoId, Long containerId, String fingerprint, String identifier,
            FindingType type, Severity severity, IssueState state) {
        issues.save(build(repoId, containerId, fingerprint, identifier, type, severity, state));
    }

    private static IssueEntity build(
            Long repoId, Long containerId, String fingerprint, String identifier,
            FindingType type, Severity severity, IssueState state) {

        IssueEntity entity = new IssueEntity();
        entity.setRepoId(repoId);
        entity.setContainerId(containerId);
        entity.setFingerprint(fingerprint);
        entity.setIdentifier(identifier == null ? null : identifier.toUpperCase(Locale.ROOT));
        entity.setType(type.wireName());
        entity.setSeverity(severity.wireName());
        entity.setState(state.wireName());
        entity.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        entity.setIsKev(false);
        entity.setFirstSeenAt(Instant.now());
        entity.setLastSeenAt(Instant.now());
        entity.setTimesSeen(1);
        return entity;
    }
}
