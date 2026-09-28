package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultRepository;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

/**
 * The newest coverage and test report of each repository, as views — what a checklist's measurement
 * reads (decision 0032 §6), without reaching this module's repositories.
 *
 * <p><b>The caller has already decided what may be read.</b> These answer for the repositories they
 * are given: a checklist asks for the repositories of a project it has refused unless wholly visible,
 * and nothing else calls them. A route never does — a route resolves a {@code Visibility} and goes
 * through {@link ReportImportService}'s history.
 *
 * <p><b>Batched by {@value #BATCH}.</b> A project's repositories are sized by the data, and an {@code
 * in} list with one bind parameter per id fails one day — PostgreSQL's driver refuses a statement past
 * 65,535 of them ({@code TargetCatalog.carryingCredentials} is the same rule).
 */
@Service
public class ReportImportCatalog {

    static final int BATCH = 1_000;

    private final CoverageImportRepository coverage;
    private final TestReportImportRepository testReports;
    private final TestSuiteResultRepository suites;

    public ReportImportCatalog(
            CoverageImportRepository coverage, TestReportImportRepository testReports, TestSuiteResultRepository suites) {
        this.coverage = coverage;
        this.testReports = testReports;
        this.suites = suites;
    }

    /** The newest coverage import per repository; a repository with none is absent from the map. */
    public Map<Long, CoverageImportView> newestCoverage(Collection<Long> repositoryIds) {
        Map<Long, CoverageImportView> newest = new HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            coverage.findNewestByRepoIdIn(batch).forEach(row -> newest.put(row.getRepoId(), CoverageImportView.of(row)));
        }
        return newest;
    }

    /** The newest test report per repository, with its suites; a repository with none is absent. */
    public Map<Long, LatestTestReport> newestTestReports(Collection<Long> repositoryIds) {
        Map<Long, LatestTestReport> newest = new HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            List<TestReportImportEntity> imports = testReports.findNewestByRepoIdIn(batch);
            if (imports.isEmpty()) {
                continue;
            }
            Map<Long, List<TestSuiteResultView>> byImport = suites
                    .findByImportIdInOrderByImportIdAscIdAsc(imports.stream().map(TestReportImportEntity::getId).toList())
                    .stream()
                    .map(TestSuiteResultView::of)
                    .collect(Collectors.groupingBy(TestSuiteResultView::importId));
            for (TestReportImportEntity row : imports) {
                newest.put(row.getRepoId(), new LatestTestReport(TestReportImportView.of(row),
                        byImport.getOrDefault(row.getId(), List.of())));
            }
        }
        return newest;
    }

    private static List<List<Long>> batches(Collection<Long> repositoryIds) {
        List<Long> distinct = new ArrayList<>(new LinkedHashSet<>(repositoryIds));
        List<List<Long>> batches = new ArrayList<>();
        for (int from = 0; from < distinct.size(); from += BATCH) {
            batches.add(distinct.subList(from, Math.min(distinct.size(), from + BATCH)));
        }
        return batches;
    }
}
