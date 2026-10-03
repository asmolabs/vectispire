package com.asmolabs.vectispire.core.plugins;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.CoveragePackageEntity;
import com.asmolabs.vectispire.core.plugins.persistence.CoveragePackageRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultRepository;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The coverage and test-report tables on a real engine (decision 0032 §7): the newest import per
 * repository, asked for seventy thousand repositories, and the purge that takes a repository's
 * suites through its imports before the imports themselves.
 *
 * <p>The identifiers come from a project's repositories, which the data sizes: one bind parameter
 * each, so {@link ReportImportCatalog} batches them. PostgreSQL is the engine that refuses the
 * unbatched statement ("at most 65 535 parameters"); MySQL's client-side statements accept it, so a
 * green run on MySQL alone says nothing of the batching. The correlated {@code max(id)} and the
 * purge's subquery are what MySQL checks. A coverage import's packages (V70) are read back with the
 * top level's empty path and a path at the column's bound, which an engine could pad, trim or refuse.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("coverage and test-report imports on the engine")
class ReportImportsIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant AT = Instant.parse("2026-09-28T10:00:00Z");

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
    private ReportImportCatalog catalog;

    @Autowired
    private CoverageImportRepository coverage;

    @Autowired
    private TestReportImportRepository testReports;

    @Autowired
    private CoveragePackageRepository packages;

    @Autowired
    private TestSuiteResultRepository suites;

    @Autowired
    private TransactionTemplate transactions;

    @BeforeEach
    void empty() {
        suites.deleteAll();
        packages.deleteAll();
        testReports.deleteAll();
        coverage.deleteAll();
    }

    @Test
    @DisplayName("past every engine's bind limit, the newest import of each repository, with its suites")
    void newestPerRepository() {
        coverage(1, 10, null);
        long newestOfOne = coverage(1, 20, 4L);
        long onlyOfTwo = coverage(2, 30, null);
        long olderReport = testReport(1, "com.example.OldTest");
        long newestReport = testReport(1, "com.example.AppTest", "com.example.OtherTest");

        List<Long> ids = new ArrayList<>();
        ids.add(1L);
        ids.addAll(LongStream.rangeClosed(1_000_000, 1_070_000).boxed().toList());
        ids.add(2L);

        Map<Long, CoverageImportView> newest = catalog.newestCoverage(ids);
        assertThat(newest).containsOnlyKeys(1L, 2L);
        assertThat(newest.get(1L).id()).isEqualTo(newestOfOne);
        assertThat(newest.get(1L).branchesTotal()).isEqualTo(4L);
        assertThat(newest.get(2L).id()).isEqualTo(onlyOfTwo);
        assertThat(newest.get(2L).branchesTotal()).as("no branch counted stays null on the engine").isNull();

        Map<Long, LatestTestReport> reports = catalog.newestTestReports(ids);
        assertThat(reports).containsOnlyKeys(1L);
        assertThat(reports.get(1L).report().id()).isEqualTo(newestReport).isNotEqualTo(olderReport);
        assertThat(reports.get(1L).suites()).extracting(TestSuiteResultView::name)
                .containsExactly("com.example.AppTest", "com.example.OtherTest");
        assertThat(catalog.newestTestReports(List.of())).isEmpty();
    }

    @Test
    @DisplayName("an import's packages read back by path, the empty top level and a path at the column's bound intact")
    void packagesByPath() {
        long imported = coverage(3, 5, null);
        String longest = "org/" + "p".repeat(996);
        coveragePackage(imported, "org/example/service", 4);
        coveragePackage(imported, "", 1);
        coveragePackage(imported, longest, 0);

        assertThat(catalog.coveragePackages(imported)).extracting(CoveragePackageView::path)
                .containsExactly("", "org/example/service", longest);
        assertThat(catalog.coveragePackages(imported).getFirst().linesCovered()).isEqualTo(1);
        assertThat(catalog.coveragePackages(imported).getFirst().branchesTotal()).as("not 0 of 0").isNull();
    }

    @Test
    @DisplayName("a repository's purge takes its suites and packages through its imports, then the imports, and nobody else's")
    void purge() {
        testReport(7, "a".repeat(500));
        long kept = testReport(8, "com.example.KeptTest");
        coveragePackage(coverage(7, 1, null), "org/example/gone", 1);
        long keptCoverage = coverage(8, 1, null);
        coveragePackage(keptCoverage, "org/example/kept", 1);

        transactions.executeWithoutResult(status -> {
            suites.deleteByRepository(7);
            testReports.deleteByRepository(7);
            packages.deleteByRepository(7);
            coverage.deleteByRepository(7);
        });

        assertThat(testReports.findAll()).extracting(TestReportImportEntity::getRepoId).containsExactly(8L);
        assertThat(suites.findAll()).extracting(TestSuiteResultEntity::getImportId).containsExactly(kept);
        assertThat(coverage.findAll()).extracting(CoverageImportEntity::getRepoId).containsExactly(8L);
        assertThat(packages.findAll()).extracting(CoveragePackageEntity::getImportId).containsExactly(keptCoverage);
    }

    private void coveragePackage(long importId, String path, long covered) {
        CoveragePackageEntity row = new CoveragePackageEntity();
        row.setImportId(importId);
        row.setPath(path);
        row.setLinesCovered(covered);
        row.setLinesTotal(covered + 1);
        packages.save(row);
    }

    private long coverage(long repositoryId, long covered, Long branchesTotal) {
        CoverageImportEntity row = new CoverageImportEntity();
        row.setSourceId(1L);
        row.setSourceSlug("ledger-ci");
        row.setRepoId(repositoryId);
        row.setFormat("jacoco");
        row.setLinesCovered(covered);
        // Past an int: a count is a bigint, on every engine.
        row.setLinesTotal(3_000_000_000L);
        row.setBranchesCovered(branchesTotal == null ? null : 1L);
        row.setBranchesTotal(branchesTotal);
        row.setDocumentSha256("0".repeat(64));
        row.setImportedAt(AT);
        row.setImportedBy("pipeline");
        row.setApiKeyId(UUID.randomUUID());
        return coverage.save(row).getId();
    }

    private long testReport(long repositoryId, String... suiteNames) {
        TestReportImportEntity row = new TestReportImportEntity();
        row.setSourceId(1L);
        row.setSourceSlug("ledger-ci");
        row.setRepoId(repositoryId);
        row.setFormat("junit-zip");
        row.setDocumentsCount(suiteNames.length);
        row.setSuitesCount(suiteNames.length);
        row.setTestsCount(suiteNames.length);
        row.setDocumentSha256("0".repeat(64));
        row.setImportedAt(AT);
        row.setImportedBy("pipeline");
        row.setApiKeyId(UUID.randomUUID());
        long id = testReports.save(row).getId();
        for (String name : suiteNames) {
            TestSuiteResultEntity suite = new TestSuiteResultEntity();
            suite.setImportId(id);
            suite.setName(name);
            suite.setTestsCount(1);
            suites.save(suite);
        }
        return id;
    }
}
