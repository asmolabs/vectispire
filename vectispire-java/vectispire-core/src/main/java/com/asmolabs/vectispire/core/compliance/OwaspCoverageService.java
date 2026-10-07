package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.rules.RuleCoverageService;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Builds the OWASP grid from what this deployment actually measures.
 *
 * <p>The rules are in {@link OwaspCoverage} and are pure. What is here is the reading — and the
 * two questions it answers are the ones that decide whether a green square means anything:
 * <b>has anything been scanned at all</b>, and <b>is each detector switched on and able to
 * reach this estate</b>.
 *
 * <p>The second is why {@link RuleCoverageService} is a dependency, and it now carries a third
 * question with it: <b>which categories the installed rules declare</b>. Code analysis that runs
 * with no rule reaching the languages present returns zero findings, and a grid taking that at
 * face value would report the categories those rules cover as clean.
 */
@Service
public class OwaspCoverageService {

    private final IssueCatalog issues;
    private final ScanCatalog scans;
    private final RuleCoverageService ruleCoverage;
    private final SettingsService settings;
    private final OwaspScopes scopes;

    public OwaspCoverageService(
            IssueCatalog issues,
            ScanCatalog scans,
            RuleCoverageService ruleCoverage,
            SettingsService settings,
            OwaspScopes scopes) {
        this.issues = issues;
        this.scans = scans;
        this.ruleCoverage = ruleCoverage;
        this.settings = settings;
        this.scopes = scopes;
    }

    /**
     * What a grid reads that does not depend on whose grid it is: the two settings, the rules'
     * reach and their declared categories, and which targets have been scanned.
     *
     * <p><b>Read once and handed to every grid of a pass.</b> The weekly record builds one grid per
     * target, and asking these per target would read every target's latest scan once for each target —
     * a pass quadratic in the estate, for an answer that does not change between two targets.
     *
     * @param scanned every target with a scan, read from each one's latest
     */
    public record Reading(
            boolean endOfLifeEnabled, boolean codeAnalysisReaches, Set<String> declaredByRules, Set<ScanTarget> scanned) {

        public Reading {
            declaredByRules = Set.copyOf(declaredByRules);
            scanned = Set.copyOf(scanned);
        }
    }

    @Transactional(readOnly = true)
    public Reading reading() {
        return new Reading(
                settings.isEnabled(Setting.EOL_ENABLED),
                settings.isEnabled(Setting.SAST_ENABLED)
                        && ruleCoverage.assess().state() != RuleCoverage.State.UNCONFIGURED,
                // **What the installed rules declare, not what the findings carry.** Deriving the
                // set of categories from the findings would drop a category out of the grid the day
                // its last finding is fixed — that is, at the moment it most deserves to say
                // "looked at, nothing to report".
                ruleCoverage.declaredOwaspCategories(),
                scanned());
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
     * <p><b>Every count is narrowed, the {@code scanned} flag included.</b> The scope's visibility —
     * the reader's intersected with the scope's targets — is the one the whole grid is computed with,
     * so a project whose targets were never scanned reads unmeasured even where its neighbours are
     * covered, and its findings are its own: a project's grid reporting another project's evidence is
     * the defect the estate's grid already refuses between readers.
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
        // estate is covered — otherwise the grid reports somebody else's evidence under their name.
        return grid(allowed, reading, true, reading.scanned().stream().anyMatch(allowed::permits));
    }

    /**
     * One target's grid, its open findings counted twice: as the grid counts them, and with the
     * settled ones — which the weekly record keeps apart rather than dropping them.
     *
     * <p>The same {@link OwaspCoverage#assess} as the screen's grid, narrowed to the one target by the
     * visibility every count already carries; nothing of the placement is restated here.
     */
    @Transactional(readOnly = true)
    public List<OwaspCoverage.Split> ofTarget(ScanTarget target, Reading reading) {
        Visibility only = Visibility.only(Set.of(target));
        if (reading.scanned().contains(target)) {
            return OwaspCoverage.split(grid(only, reading, true, true), grid(only, reading, false, true));
        }
        // A target nothing scanned: not measured, with the findings the estate's grid counts once anything
        // beside it is scanned — `OwaspCoverage.unscanned` says why, and `acrossTargets` adds them back
        // only where the grid would.
        return OwaspCoverage.unscanned(OwaspCoverage.split(grid(only, reading, true, true), grid(only, reading, false, true)));
    }

    private OwaspCoverage.Grid grid(Visibility allowed, Reading reading, boolean excludeSettled, boolean scanned) {
        Map<FindingType, Long> open = new EnumMap<>(FindingType.class);
        for (FindingType type : FindingType.values()) {
            OwaspCoverage.categoryOf(type).ifPresent(category -> open.put(type, countOpen(type, allowed, excludeSettled)));
        }

        return OwaspCoverage.assess(new OwaspCoverage.Measurement(
                scanned,
                reading.endOfLifeEnabled(),
                reading.codeAnalysisReaches(),
                Map.copyOf(open),
                reading.declaredByRules(),
                openByCategory(allowed, excludeSettled)));
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

    /** Every target with a scan, from each one's latest. */
    private Set<ScanTarget> scanned() {
        return java.util.stream.Stream.concat(
                        scans.latestPerRepository().stream()
                                .filter(row -> row.targetId() != null)
                                .<ScanTarget>map(row -> new ScanTarget.Repository(row.targetId())),
                        scans.latestPerContainer().stream()
                                .filter(row -> row.targetId() != null)
                                .<ScanTarget>map(row -> new ScanTarget.Container(row.targetId())))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private long countOpen(FindingType type, Visibility allowed, boolean excludeSettled) {
        return issues.count(new IssueFilters(
                        IssueState.OPEN.wireName(), null, type.wireName(), null, null, null,
                        false, false, null, excludeSettled, Map.of(), allowed));
    }
}
