package com.asmolabs.vectispire.core.threatintel;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssFleetSummary;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssPrioritizedIssue;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.IssueRows;
import com.asmolabs.vectispire.core.services.issues.IssueCatalog;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntels;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service orchestrating EPSS (Exploit Prediction Scoring System) and CISA KEV
 * prioritization across all monitored enterprise assets.
 */
@Service
public class EpssPrioritizationService {

    private final IssueCatalog issuesRepo;
    private final ThreatIntels intelRepo;
    private final ThreatIntelFeedService threatIntelService;
    private final TargetCatalog targets;

    public EpssPrioritizationService(
            IssueCatalog issuesRepo,
            ThreatIntels intelRepo,
            ThreatIntelFeedService threatIntelService,
            TargetCatalog targets) {
        this.issuesRepo = issuesRepo;
        this.intelRepo = intelRepo;
        this.threatIntelService = threatIntelService;
        this.targets = targets;
    }

    /**
     * How many ranked issues the summary carries.
     *
     * <p><b>The record already said this.</b> The field is called {@code topPriorities} and it
     * returned every open issue in the deployment — 620 ranked rows for a 620-issue estate, which
     * is not a top of anything. The aggregate counts below still weigh every issue; only the list
     * is cut, and {@code totalVulnerabilities} carries the true figure beside it so nothing is
     * hidden by the cut.
     */
    private static final int RANKED = 50;

    /**
     * The fleet's exploitation-probability ranking, <b>within the caller's allowance</b>.
     *
     * <p>The read was every issue in the deployment with the open test applied in Java, and no
     * visibility at all — so a restricted reader received a ranked list of every other target's
     * most exploitable vulnerabilities, which is the most actionable form the backlog takes.
     */
    @Transactional(readOnly = true)
    public EpssFleetSummary getFleetSummary(Visibility allowed) {
        // **A projection, not a row.** This read materialised a managed IssueEntity per issue to
        // rank on twelve columns — 23, 223 then 623 entity loads for 20, 220 and 620 issues.
        //
        // **Settled triage is left out**, as on the scorecard, the maturity ranking and the gate. The
        // ranking used to keep every issue not closed or resolved, dismissals included, so a CVE
        // argued `not_affected` could head the list of what to fix first — the most actionable
        // screen contradicting the decision already taken about the row. `pending_approval` and
        // any status this version does not know still rank: neither is a decision.
        List<IssueRows.EpssRow> openIssues = issuesRepo.rows(
                        new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), allowed), IssueRows.EpssRow.class)
                .stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                .toList();

        // Named by the targets these issues actually belong to, rather than by reading every
        // repository and every container in the deployment to look two of them up.
        Map<Long, RepositoryView> reposMap = byId(
                targets.repositories(idsOf(openIssues, IssueRows.EpssRow::repoId)), RepositoryView::id);
        Map<Long, ContainerView> containersMap = byId(
                targets.containers(idsOf(openIssues, IssueRows.EpssRow::containerId)), ContainerView::id);

        // **One query for the intel, not one per issue.** This loop asked `lookupCve` per row —
        // 18, 168 then 468 queries for 20, 220 and 620 issues, measured with the Hibernate
        // counters. The answer never depended on the order it was asked in, so it is asked once.
        Map<String, ThreatIntelRecord> intelByCve = threatIntelService.lookupCves(
                openIssues.stream().map(IssueRows.EpssRow::identifier).toList());

        List<EpssPrioritizedIssue> prioritized = new ArrayList<>();
        Map<String, Integer> tierBreakdown = new HashMap<>(Map.of(
                "CRITICAL_ARMED", 0,
                "HIGH_PROBABLE", 0,
                "MEDIUM_THEORETICAL", 0,
                "LOW_PROBABILITY", 0));

        int activeKevCount = 0;
        int highEpssCount = 0;
        int reachableEpssCount = 0;
        double totalEpss = 0.0;
        int epssCount = 0;

        for (IssueRows.EpssRow issue : openIssues) {
            String cveId = issue.identifier();
            Double cvss = issue.cvssScore();

            Optional<ThreatIntelRecord> intel = cveId != null
                    ? Optional.ofNullable(intelByCve.get(cveId.trim().toLowerCase(Locale.ROOT)))
                    : Optional.empty();
            boolean isKev = Boolean.TRUE.equals(issue.isKev()) || (intel.isPresent() && intel.get().isKev());
            // **Unknown stays unknown.** A CVE absent from the feed was reported with an EPSS of
            // 0.01 and a percentile made up as `score × 1.1` — a figure no feed published, shown
            // beside real ones, averaged into the fleet mean and read by an operator as a
            // measurement. The ranking still needs a number to sort on, and the risk matrix
            // supplies its own default for that; what is *reported* is what was measured, or null.
            Double epssScore = issue.epssScore() != null
                    ? issue.epssScore()
                    : intel.map(ThreatIntelRecord::epssScore).orElse(null);
            Double epssPercentile = intel.map(ThreatIntelRecord::epssPercentile).orElse(null);

            String reachability = issue.reachability() != null ? issue.reachability() : "UNKNOWN";
            boolean isReachable = "REACHABLE".equalsIgnoreCase(reachability);

            if (isKev) activeKevCount++;
            if (epssScore != null && epssScore >= 0.20) {
                highEpssCount++;
                if (isReachable) reachableEpssCount++;
            }
            if (epssScore != null) {
                totalEpss += epssScore;
                epssCount++;
            }

            int score = EpssRiskMatrix.calculatePriorityScore(cvss, epssScore, isKev, reachability);
            String tier = EpssRiskMatrix.determineTier(cvss, epssScore, isKev, reachability);
            EpssRiskMatrix.RecommendedAction action = EpssRiskMatrix.determineAction(tier, isKev, reachability);

            tierBreakdown.put(tier, tierBreakdown.getOrDefault(tier, 0) + 1);

            String targetName = issue.repoId() != null && reposMap.containsKey(issue.repoId())
                    ? reposMap.get(issue.repoId()).name()
                    : (issue.containerId() != null && containersMap.containsKey(issue.containerId())
                            ? containersMap.get(issue.containerId()).imageName() + ":" + containersMap.get(issue.containerId()).tag()
                            : "target-" + (issue.repoId() != null ? issue.repoId() : issue.containerId()));

            String targetKind = issue.repoId() != null ? "REPOSITORY" : "CONTAINER";

            prioritized.add(new EpssPrioritizedIssue(
                    issue.id(),
                    cveId != null ? cveId : issue.type(),
                    issue.description() != null ? issue.description() : (issue.packageName() != null ? issue.packageName() : "Vulnerability " + issue.id()),
                    issue.severity(),
                    cvss,
                    epssScore,
                    epssPercentile,
                    isKev,
                    reachability,
                    targetName,
                    targetKind,
                    score,
                    tier,
                    action));
        }

        prioritized.sort(Comparator.comparingInt(EpssPrioritizedIssue::priorityScore).reversed());

        double avgEpss = epssCount > 0 ? (totalEpss / epssCount) : 0.0;

        return new EpssFleetSummary(
                openIssues.size(),
                activeKevCount,
                highEpssCount,
                reachableEpssCount,
                Math.round(avgEpss * 1000.0) / 1000.0,
                // Ranked over everything, returned as the top of the ranking. Cutting before the
                // sort would return fifty arbitrary issues and call them the worst.
                prioritized.stream().limit(RANKED).toList(),
                tierBreakdown);
    }

    private static List<Long> idsOf(
            List<IssueRows.EpssRow> rows, java.util.function.Function<IssueRows.EpssRow, Long> id) {
        return rows.stream().map(id).filter(java.util.Objects::nonNull).distinct().toList();
    }

    private static <T> Map<Long, T> byId(List<T> entities, java.util.function.Function<T, Long> id) {
        return entities.stream().collect(Collectors.toMap(id, e -> e));
    }

    public Optional<ThreatIntelRecord> lookupCve(String cveId) {
        return threatIntelService.lookupCve(cveId);
    }
}
