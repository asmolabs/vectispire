package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.rules.RuleCoverageService;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Builds the OWASP grid from what this deployment actually measures.
 *
 * <p>The rules are in {@link OwaspCoverage} and are pure. What is here is the reading — and the
 * two questions it answers are the ones that decide whether a green square means anything:
 * <b>what the latest scan of each target examined</b>, and <b>is each detector switched on and able to
 * reach this estate</b>.
 *
 * <p>The first is asked target by target, of the scan's own record ({@code examined_types}, decision
 * 0032 §6): a category read "nothing found" as soon as anything in scope had a scan, so an image-only
 * project — whose scans read dependencies alone — showed secrets and misconfiguration as clean, and a
 * repository whose secret step failed showed A07 clean on the strength of the steps that did not.
 *
 * <p>The second is why {@link RuleCoverageService} is a dependency, and it carries a third question with
 * it: <b>which categories the installed rules declare, for which language</b>. Code analysis that runs
 * with no rule reaching the languages present returns zero findings, and a grid taking that at face value
 * would report the categories those rules cover as clean — which one global flag did, for every Java
 * project, the day a Python rule declaring A03 was installed.
 */
@Service
public class OwaspCoverageService {

    private final IssueCatalog issues;
    private final ScanCatalog scans;
    private final TargetCatalog targets;
    private final RuleCoverageService ruleCoverage;
    private final SettingsService settings;
    private final OwaspScopes scopes;

    public OwaspCoverageService(
            IssueCatalog issues,
            ScanCatalog scans,
            TargetCatalog targets,
            RuleCoverageService ruleCoverage,
            SettingsService settings,
            OwaspScopes scopes) {
        this.issues = issues;
        this.scans = scans;
        this.targets = targets;
        this.ruleCoverage = ruleCoverage;
        this.settings = settings;
        this.scopes = scopes;
    }

    /**
     * What a grid reads that does not depend on whose grid it is: the two settings, the rules' declared
     * categories, and every target's evidence.
     *
     * <p><b>Read once and handed to every grid of a pass.</b> The weekly record builds one grid per
     * target, and asking these per target would read every target's latest scan once for each target —
     * a pass quadratic in the estate, for an answer that does not change between two targets.
     *
     * @param codeAnalysisEnabled code analysis is on and more than the shipped rule is installed — the
     *     deployment's half; each target's evidence says whether a rule reaches its languages
     * @param evidence every target that exists, from each one's newest finished scan — a target with
     *     none reads never scanned
     */
    public record Reading(
            boolean endOfLifeEnabled,
            boolean codeAnalysisEnabled,
            Set<String> declaredByRules,
            Map<ScanTarget, OwaspCoverage.Evidence> evidence) {

        public Reading {
            declaredByRules = Set.copyOf(declaredByRules);
            evidence = Map.copyOf(evidence);
        }

        /** A target's evidence; one created since this reading was taken has none, and is never scanned. */
        OwaspCoverage.Evidence of(ScanTarget target) {
            return evidence.getOrDefault(target, OwaspCoverage.Evidence.neverScanned(target));
        }

        /**
         * Whether code analysis reaches the repositories it examined, for the monthly compliance record.
         *
         * <p><b>The same reading as the grid's, without the categories</b>: on, more than the shipped rule
         * installed, and — for every repository whose newest finished scan completed its code analysis and
         * recorded the languages — its rules read a language of its tree. One global flag answered true
         * for a Java estate the day a Python rule set was installed. A repository that was not examined is
         * left out rather than counted against the rules: the record's sentence names a detector switched
         * off or a language no rule covers, and a failed scan is neither.
         */
        public boolean codeAnalysisReachesItsRepositories() {
            if (!codeAnalysisEnabled) {
                return false;
            }
            List<OwaspCoverage.Evidence> read = evidence.values().stream()
                    .filter(one -> one.target() instanceof ScanTarget.Repository)
                    .filter(one -> one.examined().map(types -> types.contains(FindingType.SAST)).orElse(false))
                    .filter(one -> one.analysed().isPresent())
                    .toList();
            return !read.isEmpty() && read.stream().allMatch(one -> !one.analysed().get().isEmpty());
        }
    }

    @Transactional(readOnly = true)
    public Reading reading() {
        Map<Language, Set<String>> byLanguage = ruleCoverage.declaredOwaspCategoriesByLanguage();
        return new Reading(
                settings.isEnabled(Setting.EOL_ENABLED),
                settings.isEnabled(Setting.SAST_ENABLED)
                        && ruleCoverage.assess().state() != RuleCoverage.State.UNCONFIGURED,
                // **What the installed rules declare, not what the findings carry.** Deriving the
                // set of categories from the findings would drop a category out of the grid the day
                // its last finding is fixed — that is, at the moment it most deserves to say
                // "looked at, nothing to report".
                ruleCoverage.declaredOwaspCategories(),
                evidence(byLanguage));
    }

    /**
     * The grid and the scope it was computed over.
     *
     * @param scope the project or solution as far as the reader sees it, null for the reader's estate —
     *     the weekly route's record, so the screen reads both alike
     */
    public record ScopedGrid(OwaspCoverage.Grid grid, OwaspWeeklyHistoryService.OwaspWeeklyScope scope) {}

    /**
     * The grid over one project or solution, or over the reader's estate when neither is named.
     *
     * <p><b>Every count is narrowed, the evidence included.</b> The scope's visibility — the reader's
     * intersected with the scope's targets — is the one the whole grid is computed with, so a project
     * whose targets were never examined reads unmeasured even where its neighbours are covered, and its
     * findings are its own: a project's grid reporting another project's evidence is the defect the
     * estate's grid already refuses between readers.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException for both a project
     *     and a solution
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException for a project or a
     *     solution that does not exist and one the reader sees nothing of, in the same words
     */
    @Transactional(readOnly = true)
    public ScopedGrid grid(Long projectId, Long solutionId, VisibilityService.Allowance allowance) {
        OwaspScopes.Scoped scoped = scopes.resolve(projectId, solutionId, allowance);
        return new ScopedGrid(grid(scoped.visibility()), scoped.stated());
    }

    @Transactional(readOnly = true)
    public OwaspCoverage.Grid grid(Visibility allowed) {
        Reading reading = reading();
        // **Asked of the estate and not of the deployment.** A restricted reader whose two repositories
        // were never scanned must be told their categories are unmeasured, even where the rest of the
        // estate is covered — otherwise the grid reports somebody else's evidence under their name. The
        // targets are those that exist: a visibility naming one deleted since adds no evidence.
        List<OwaspCoverage.Evidence> inScope = reading.evidence().values().stream()
                .filter(evidence -> allowed.permits(evidence.target()))
                .toList();
        return OwaspCoverage.assess(measurement(allowed, reading, true, inScope));
    }

    /**
     * One target's grid, its open findings counted twice: as the grid counts them, and with the
     * settled ones — which the weekly record keeps apart rather than dropping them.
     *
     * <p>The same rule as the screen's grid ({@link OwaspCoverage#assessTarget}), narrowed to the one
     * target by the visibility every count already carries and by its own evidence; nothing of the
     * placement is restated here. A scope's grid is the fold of these lines ({@code acrossTargets}).
     */
    @Transactional(readOnly = true)
    public List<OwaspCoverage.Split> ofTarget(ScanTarget target, Reading reading) {
        Visibility only = Visibility.only(Set.of(target));
        List<OwaspCoverage.Evidence> evidence = List.of(reading.of(target));
        return OwaspCoverage.split(
                OwaspCoverage.assessTarget(measurement(only, reading, true, evidence)),
                OwaspCoverage.assessTarget(measurement(only, reading, false, evidence)));
    }

    private OwaspCoverage.Measurement measurement(
            Visibility allowed, Reading reading, boolean excludeSettled, List<OwaspCoverage.Evidence> evidence) {
        Map<FindingType, Long> open = new EnumMap<>(FindingType.class);
        for (FindingType type : FindingType.values()) {
            OwaspCoverage.categoryOf(type).ifPresent(category -> open.put(type, countOpen(type, allowed, excludeSettled)));
        }

        return new OwaspCoverage.Measurement(
                reading.endOfLifeEnabled(),
                reading.codeAnalysisEnabled(),
                Map.copyOf(open),
                reading.declaredByRules(),
                openByCategory(allowed, excludeSettled),
                evidence);
    }

    /**
     * The open code findings, by declared category.
     *
     * <p>Grouped in the database: at most ten rows whatever the size of the backlog, and the
     * reader's visibility is carried by the same filter as everywhere else.
     */
    private Map<String, Long> openByCategory(Visibility allowed, boolean excludeSettled) {
        return issues.countOpenSastByOwaspCategory(new IssueFilters(
                        IssueState.OPEN.wireName(), null, null, null, null, null,
                        false, false, null, excludeSettled, Map.of(), allowed)).stream()
                .collect(java.util.stream.Collectors.toMap(
                        IssueAggregates.OwaspCategoryCount::category,
                        IssueAggregates.OwaspCategoryCount::count,
                        Long::sum));
    }

    /**
     * Every target's evidence, from its newest finished scan: two rollups, then the scans' outlines and
     * languages, a thousand identifiers per statement ({@code ScanCatalog}).
     *
     * <p><b>The newest finished scan, as the gate reads it</b>, never the newest of all: a scan still
     * running has changed nothing in the backlog, and reading it would turn every scheduled re-scan into
     * minutes of "not measured".
     */
    private Map<ScanTarget, OwaspCoverage.Evidence> evidence(Map<Language, Set<String>> byLanguage) {
        Map<ScanTarget, LatestScanRow> newest = new HashMap<>();
        scans.latestFinishedPerRepository().stream().filter(row -> row.targetId() != null)
                .forEach(row -> newest.put(new ScanTarget.Repository(row.targetId()), row));
        scans.latestFinishedPerContainer().stream().filter(row -> row.targetId() != null)
                .forEach(row -> newest.put(new ScanTarget.Container(row.targetId()), row));

        List<Long> scanIds = new ArrayList<>(newest.values().stream().map(LatestScanRow::scanId).toList());
        Map<Long, ScanCatalog.ScanOutline> outlines = scans.outlinesOf(scanIds);
        Map<Long, ScanCatalog.ScanLanguages> languages = scans.languagesOf(scanIds);

        Map<ScanTarget, OwaspCoverage.Evidence> evidence = new HashMap<>();
        java.util.stream.Stream.concat(
                        targets.repositories().stream().<ScanTarget>map(row -> new ScanTarget.Repository(row.id())),
                        targets.containers().stream().<ScanTarget>map(row -> new ScanTarget.Container(row.id())))
                .forEach(target -> {
                    LatestScanRow row = newest.get(target);
                    if (row == null) {
                        evidence.put(target, OwaspCoverage.Evidence.neverScanned(target));
                        return;
                    }
                    // A status this version does not know reads as no observation, as the gate reads it.
                    Observation observation = Observation.of(ScanStatus.fromWireName(row.status()));
                    ScanCatalog.ScanOutline outline = outlines.get(row.scanId());
                    ScanCatalog.ScanLanguages recorded = languages.get(row.scanId());
                    evidence.put(target, OwaspCoverage.Evidence.of(
                            target,
                            observation,
                            outline == null ? Optional.empty() : outline.examinedTypes(),
                            recorded == null ? Optional.empty() : recorded.detected(),
                            recorded == null ? Optional.empty() : recorded.sastRules(),
                            byLanguage));
                });
        return evidence;
    }

    private long countOpen(FindingType type, Visibility allowed, boolean excludeSettled) {
        return issues.count(new IssueFilters(
                        IssueState.OPEN.wireName(), null, type.wireName(), null, null, null,
                        false, false, null, excludeSettled, Map.of(), allowed));
    }
}
