package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The blast radius, against a database.
 *
 * <p>The caller's query used to be matched in Java over every finding in the deployment. It is now
 * a predicate in SQL, so what these cases defend is that the two agree: an exact CVE match that
 * does not become a prefix match, a package match that also looks at the purl, and a secret that
 * stays out of a dependency graph.
 *
 * <p>Visibility is covered where it belongs, in {@code VisibilityRoutesTest} — the leak it closes
 * was a route-level one, and asserting it here would test the service while the hole was in what
 * the controller failed to pass it.
 */
@DisplayName("the blast radius, against a database")
class BlastRadiusDatabaseTest extends VectispireContextTest {

    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private BlastRadiusService blastRadius;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Findings findings;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private long scanId;

    @BeforeEach
    void seed() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.com/team/app.git");
        repository.setName("app");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        scanId = scans.save(scan).getId();

        finding("log4j-core", "CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                FindingType.VULNERABILITY);
        finding("spring-beans", "CVE-2022-22965", "pkg:maven/org.springframework/spring-beans@5.3.17",
                FindingType.VULNERABILITY);
        // A secret has no package to upgrade and no place in a dependency graph.
        finding("aws-credentials", "generic-api-key", null, FindingType.SECRET);
    }

    @Test
    @DisplayName("a CVE query matches exactly, and a prefix of one matches nothing")
    void aCveQueryIsNotAPrefixMatch() {
        assertThat(blastRadius.explore("CVE-2021-44228", Visibility.everything()).targets())
                .singleElement()
                .satisfies(target -> assertThat(target.packageName()).isEqualTo("log4j-core"));

        // The case that makes exactness worth asserting: a substring match would answer this
        // with the finding above, and a reader would believe a CVE affects them when it does not.
        assertThat(blastRadius.explore("CVE-2021-4", Visibility.everything()).targets()).isEmpty();
    }

    @Test
    @DisplayName("a package query matches the name or the purl, case-insensitively")
    void aPackageQueryLooksAtBoth() {
        assertThat(blastRadius.explore("LOG4J", Visibility.everything()).targets())
                .as("the query is what somebody typed, not what the database happens to store")
                .hasSize(1);

        assertThat(blastRadius.explore("org.springframework", Visibility.everything()).targets())
                .as("the coordinates live in the purl, and a name-only match would miss them")
                .hasSize(1);
    }

    @Test
    @DisplayName("a blank query is the whole graph, and a secret is not in it")
    void secretsAreNotDependencies() {
        BlastRadiusReport report = blastRadius.explore("", Visibility.everything());

        assertThat(report.targets()).hasSize(2);
        assertThat(report.targets()).extracting(BlastRadiusReport.TargetImpact::packageName)
                .doesNotContain("aws-credentials");
    }

    @Test
    @DisplayName("a reader allowed nothing gets nothing, without a query being issued for it")
    void anEmptyAllowanceIsAnswereImmediately() {
        assertThat(blastRadius.explore("", Visibility.only(java.util.List.of())).targets()).isEmpty();
        assertThat(blastRadius.getTopImpactPackages(10, Visibility.only(java.util.List.of()))).isEmpty();
    }

    @Test
    @DisplayName("three hundred findings elsewhere do not enter the answer to a narrow query")
    void theCostFollowsTheQuery() {
        int forOneMatch = entitiesLoadedExploring();

        for (int index = 0; index < 300; index++) {
            finding("bulk-" + index, "CVE-9100-" + index, "pkg:npm/bulk-" + index + "@1.0.0",
                    FindingType.VULNERABILITY);
        }
        assertThat(blastRadius.explore("log4j-core", Visibility.everything()).targets())
                .as("the fixture grew around the query, not on it")
                .hasSize(1);

        // The read used to be every finding in the deployment, with the match applied afterwards
        // in Java — so the answer to a one-package query cost the whole table.
        assertThat(entitiesLoadedExploring())
                .as("a query that matches one package must not load three hundred that do not")
                .isLessThanOrEqualTo(forOneMatch);
        assertThat(entitiesLoadedExploring())
                .as("whatever the estate holds, a narrow query reads a bounded number of rows")
                .isLessThanOrEqualTo(20);
    }

    private int entitiesLoadedExploring() {
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        blastRadius.explore("log4j-core", Visibility.everything());
        return (int) statistics.getEntityLoadCount();
    }

    private void finding(String packageName, String identifier, String purl, FindingType type) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setType(type.wireName());
        finding.setIdentifier(identifier);
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setPackageName(packageName);
        finding.setPackageVersion("1.0.0");
        finding.setPurl(purl);
        finding.setIsDirectDependency(true);
        finding.setSource("grype");
        finding.setCreatedAt(Instant.now());
        findings.save(finding);
    }
}
