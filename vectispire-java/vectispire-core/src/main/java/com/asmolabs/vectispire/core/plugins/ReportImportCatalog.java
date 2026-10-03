package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.CoveragePackageRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportRepository;
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
 * The newest coverage and test report of each repository, and its newest SARIF import carrying a tool,
 * as views — what a checklist's measurement reads (decision 0032 §6), without reaching this module's
 * repositories.
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
    private final CoveragePackageRepository coveragePackages;
    private final TestReportImportRepository testReports;
    private final TestSuiteResultRepository suites;
    private final SarifImportRepository sarif;

    public ReportImportCatalog(CoverageImportRepository coverage, CoveragePackageRepository coveragePackages,
            TestReportImportRepository testReports, TestSuiteResultRepository suites, SarifImportRepository sarif) {
        this.coverage = coverage;
        this.coveragePackages = coveragePackages;
        this.testReports = testReports;
        this.suites = suites;
        this.sarif = sarif;
    }

    /** The newest coverage import per repository; a repository with none is absent from the map. */
    public Map<Long, CoverageImportView> newestCoverage(Collection<Long> repositoryIds) {
        Map<Long, CoverageImportView> newest = new HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            coverage.findNewestByRepoIdIn(batch).forEach(row -> newest.put(row.getRepoId(), CoverageImportView.of(row)));
        }
        return newest;
    }

    /**
     * One coverage import's packages, by path — empty for an import that kept none, which its {@code
     * packagesState} says why. One import at a time: a kept import holds up to ten thousand of them.
     */
    public List<CoveragePackageView> coveragePackages(long importId) {
        return coveragePackages.findByImportIdOrderByPathAsc(importId).stream().map(CoveragePackageView::of).toList();
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

    /**
     * The newest SARIF import of each repository whose accepted runs include the tool — {@code
     * import:<source>/<tool>}, the fingerprint's key — at any age. A repository with none is absent:
     * never imported for that tool, or only before the tools of an import were recorded, which {@link
     * #unrecordedSince} tells apart. Accepted means produced: a result-less or failed run is refused at
     * the door (decision 0017 §7).
     */
    public Map<Long, SarifImportView> newestCarrying(Collection<Long> repositoryIds, String toolKey) {
        String pattern = "%," + toolKey.replace("!", "!!").replace("%", "!%").replace("_", "!_") + ",%";
        Map<Long, SarifImportView> newest = new HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            sarif.findNewestCarrying(batch, pattern).forEach(row -> newest.put(row.getRepoId(), SarifImportView.of(row)));
        }
        return newest;
    }

    /**
     * Those of these repositories holding an import from the source, at or after {@code since},
     * accepted before the tools of an import were recorded: it may have carried the tool, and nothing
     * wrote down whether it did.
     */
    public java.util.Set<Long> unrecordedSince(Collection<Long> repositoryIds, String sourceSlug, java.time.Instant since) {
        java.util.Set<Long> unrecorded = new java.util.HashSet<>();
        for (List<Long> batch : batches(repositoryIds)) {
            unrecorded.addAll(sarif.findUnrecordedSince(batch, sourceSlug, since));
        }
        return unrecorded;
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
