package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.IssueAggregates;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.util.EnumMap;
import java.util.Map;
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

    private final Issues issues;
    private final Scans scans;
    private final RuleCoverageService ruleCoverage;
    private final SettingsService settings;

    public OwaspCoverageService(
            Issues issues, Scans scans, RuleCoverageService ruleCoverage, SettingsService settings) {
        this.issues = issues;
        this.scans = scans;
        this.ruleCoverage = ruleCoverage;
        this.settings = settings;
    }

    @Transactional(readOnly = true)
    public OwaspCoverage.Grid grid(Visibility allowed) {
        Map<FindingType, Long> open = new EnumMap<>(FindingType.class);
        for (FindingType type : FindingType.values()) {
            OwaspCoverage.categoryOf(type).ifPresent(category -> open.put(type, countOpen(type, allowed)));
        }

        return OwaspCoverage.assess(new OwaspCoverage.Measurement(
                scanned(allowed),
                settings.isEnabled(Setting.EOL_ENABLED),
                settings.isEnabled(Setting.SAST_ENABLED)
                        && ruleCoverage.assess().state() != RuleCoverage.State.UNCONFIGURED,
                Map.copyOf(open),
                // **What the installed rules declare, not what the findings carry.** Deriving the
                // set of categories from the findings would drop a category out of the grid the day
                // its last finding is fixed — that is, at the moment it most deserves to say
                // "looked at, nothing to report".
                ruleCoverage.declaredOwaspCategories(),
                openByCategory(allowed)));
    }

    /**
     * The open code findings, by declared category.
     *
     * <p>Grouped in the database: at most ten rows whatever the size of the backlog, and the
     * reader's visibility is carried by the same filter as everywhere else.
     */
    private Map<String, Long> openByCategory(Visibility allowed) {
        return issues.countOpenSastByOwaspCategory(new IssueFilters(
                        IssueState.OPEN.wireName(), null, null, null, null, null,
                        false, false, null, true, Map.of(), allowed)
                .toSpecification()).stream()
                .collect(java.util.stream.Collectors.toMap(
                        IssueAggregates.OwaspCategoryCount::category,
                        IssueAggregates.OwaspCategoryCount::count,
                        Long::sum));
    }

    /**
     * Whether anything the caller may see has ever been scanned.
     *
     * <p><b>Asked of the estate and not of the deployment.</b> A restricted reader whose two
     * repositories were never scanned must be told their categories are unmeasured, even where
     * the rest of the estate is covered — otherwise the grid reports somebody else's evidence
     * under their name.
     */
    private boolean scanned(Visibility allowed) {
        return java.util.stream.Stream.concat(
                        scans.findLatestPerRepository().stream()
                                .filter(row -> row.targetId() != null)
                                .<ScanTarget>map(row -> new ScanTarget.Repository(row.targetId())),
                        scans.findLatestPerContainer().stream()
                                .filter(row -> row.targetId() != null)
                                .<ScanTarget>map(row -> new ScanTarget.Container(row.targetId())))
                .anyMatch(allowed::permits);
    }

    private long countOpen(FindingType type, Visibility allowed) {
        return issues.count(new IssueFilters(
                        IssueState.OPEN.wireName(), null, type.wireName(), null, null, null,
                        false, false, null, true, Map.of(), allowed)
                .toSpecification());
    }
}
