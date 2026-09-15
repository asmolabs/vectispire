package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
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
 * <p>The second is why {@link RuleCoverageService} is a dependency. Code analysis that runs with
 * no rule reaching the languages present returns zero findings, and a grid taking that at face
 * value would report the categories it covers as clean. It covers none of them today, so the
 * question is moot — and it will not stay moot, which is why the wiring is here rather than
 * waiting.
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
                Map.copyOf(open)));
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
