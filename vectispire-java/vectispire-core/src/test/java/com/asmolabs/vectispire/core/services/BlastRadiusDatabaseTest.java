package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.util.List;
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
    private Containers containers;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private long scanId;
    private long repoId;

    @BeforeEach
    void seed() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.com/team/app.git");
        repository.setName("app");
        repository.setBranch("main");
        repoId = repositories.save(repository).getId();

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

    @Test
    @DisplayName("the top-impact list aggregates in the database, and loads no finding at all")
    void theTopImpactListDoesNotReadTheTable() {
        for (int index = 0; index < 300; index++) {
            finding("bulk-" + index, "CVE-9100-" + index, "pkg:npm/bulk-" + index + "@1.0.0",
                    FindingType.VULNERABILITY);
        }

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        List<BlastRadiusReport.TopImpactPackage> top =
                blastRadius.getTopImpactPackages(12, Visibility.everything());

        assertThat(top).hasSize(12);
        // The screen's landing list used to hydrate a finding and a scan for every row in the
        // deployment to display twelve. Zero is the assertion, not "fewer": the query is a
        // projection now, and an entity appearing here means somebody put the table back.
        assertThat(statistics.getEntityLoadCount())
                .as("a dozen lines must not cost the estate")
                .isZero();
    }

    @Test
    @DisplayName("the aggregate agrees with the findings it counts")
    void theAggregateCounts() {
        // A second scan of the same package, transitive this time and scored higher: the counts
        // the score is built from each have to come back distinct, and reading a tuple by the
        // wrong name would transpose them silently.
        ScanEntity second = new ScanEntity();
        second.setRepoId(repoId);
        second.setStatus(ScanStatus.COMPLETED.wireName());
        second.setBranch("main");
        second.setCreatedAt(Instant.now());
        long secondScan = scans.save(second).getId();

        FindingEntity transitive = new FindingEntity();
        transitive.setScanId(secondScan);
        transitive.setType(FindingType.VULNERABILITY.wireName());
        transitive.setIdentifier("CVE-2021-45046");
        transitive.setSeverity(Severity.HIGH.wireName());
        transitive.setPackageName("log4j-core");
        transitive.setPackageVersion("2.14.1");
        transitive.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        transitive.setIsDirectDependency(false);
        transitive.setCvssScore(9.0);
        transitive.setSource("grype");
        transitive.setCreatedAt(Instant.now());
        findings.save(transitive);

        assertThat(blastRadius.getTopImpactPackages(10, Visibility.everything()))
                .filteredOn(pkg -> pkg.packageName().equals("log4j-core"))
                .singleElement()
                .satisfies(pkg -> {
                    // **One.** Two scans of the same repository are one target, and this is the
                    // line the change is about: counting the scans put a 2 here, and thirty a
                    // month later.
                    assertThat(pkg.affectedTargetsCount())
                            .as("two scans of one repository are one target")
                            .isEqualTo(1);
                    assertThat(pkg.directUsages()).as("one direct").isEqualTo(1);
                    assertThat(pkg.transitiveUsages()).as("one transitive").isEqualTo(1);
                    assertThat(pkg.totalCves()).as("two distinct CVEs").isEqualTo(2);
                    assertThat(pkg.maxCvss()).isEqualTo(9.0);
                    assertThat(pkg.ecosystem()).isEqualTo("Maven");
                });
    }

    @Test
    @DisplayName("a package in two repositories reaches two targets, however often either is scanned")
    void reachIsCountedInTargetsNotScans() {
        // The same package in a second repository, and the first one scanned three more times.
        // Only the first of those changes what the list should say.
        long otherRepo = repository("ssh://git@example.com/team/other.git", "other");
        findingOn(scanOf(otherRepo, null), "log4j-core", "CVE-2021-44228",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true, 10.0);
        for (int index = 0; index < 3; index++) {
            findingOn(scanOf(repoId, null), "log4j-core", "CVE-2021-44228",
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true, 10.0);
        }

        assertThat(blastRadius.getTopImpactPackages(10, Visibility.everything()))
                .filteredOn(pkg -> pkg.packageName().equals("log4j-core"))
                .singleElement()
                .satisfies(pkg -> assertThat(pkg.affectedTargetsCount())
                        .as("two repositories, five scans between them")
                        .isEqualTo(2));
    }

    @Test
    @DisplayName("a container and a repository are two targets, not one of each counted apart")
    void repositoriesAndContainersAddUp() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("registry.example.com/team/app");
        image.setTag("1.4.0");
        long containerId = containers.save(image).getId();

        findingOn(scanOf(null, containerId), "log4j-core", "CVE-2021-44228",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", false, 10.0);

        // The two counts come back from the database apart, because a scan names one column or
        // the other; a caller that read only one of them would report half the reach.
        assertThat(blastRadius.getTopImpactPackages(10, Visibility.everything()))
                .filteredOn(pkg -> pkg.packageName().equals("log4j-core"))
                .singleElement()
                .satisfies(pkg -> assertThat(pkg.affectedTargetsCount())
                        .as("one repository and one image")
                        .isEqualTo(2));
    }

    private long repository(String url, String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scanOf(Long repository, Long container) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository);
        scan.setContainerId(container);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        return scans.save(scan).getId();
    }

    private void findingOn(
            long scan, String packageName, String identifier, String purl, boolean direct, double cvss) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier(identifier);
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setPackageName(packageName);
        finding.setPackageVersion("2.14.1");
        finding.setPurl(purl);
        finding.setIsDirectDependency(direct);
        finding.setCvssScore(cvss);
        finding.setSource("grype");
        finding.setCreatedAt(Instant.now());
        findings.save(finding);
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
