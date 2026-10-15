package com.asmolabs.vectispire.core.threatintel.web;

import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssFleetSummary;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssPrioritizedIssue;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.RecommendedAction;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import java.util.Map;

/**
 * The fleet's exploitation ranking, as the wire carries it — the domain records field for field,
 * published under the same schema names, with the claims the domain module cannot write down.
 *
 * <p><b>Three scores of a ranked issue are null when nobody measured them</b>
 * ({@code EpssPrioritizationService}: "unknown stays unknown"): the CVSS score when no advisory gave
 * one, the EPSS score and percentile when neither the scan nor the feed has the CVE. The document said
 * {@code number} of all three, and the client had to say otherwise by hand. {@code vectispire-common}
 * depends on no web annotation, so {@code @Schema} cannot sit on {@link EpssPrioritizedIssue} — the
 * reason {@code SecurityDebtReportView} gives too.
 *
 * <p>Every other field is never null: the identifier falls back to the issue's type, the title to the
 * package and then to the issue's number, the target is named by {@code TargetNaming} or by its number,
 * and the tier and the action are computed.
 */
@Schema(name = "EpssFleetSummary")
public record EpssFleetSummaryView(
        int totalVulnerabilities,
        int activeKevCount,
        int highEpssCount,
        double averageFleetEpss,
        List<EpssPrioritizedIssueView> topPriorities,
        Map<String, Integer> breakdownByTier) {

    public static EpssFleetSummaryView of(EpssFleetSummary summary) {
        return new EpssFleetSummaryView(
                summary.totalVulnerabilities(),
                summary.activeKevCount(),
                summary.highEpssCount(),
                summary.averageFleetEpss(),
                summary.topPriorities().stream().map(EpssPrioritizedIssueView::of).toList(),
                summary.breakdownByTier());
    }

    /** @see EpssPrioritizedIssue */
    @Schema(name = "EpssPrioritizedIssue")
    public record EpssPrioritizedIssueView(
            Long issueId,
            String identifier,
            String title,
            String severity,
            @Schema(types = {"number", "null"}, format = "double", description = "Null when no advisory gave one.")
                    Double cvssScore,
            @Schema(types = {"number", "null"}, format = "double", description = "Null when neither the scan nor the EPSS feed scores the CVE.")
                    Double epssScore,
            @Schema(types = {"number", "null"}, format = "double", description = "Null when the EPSS feed does not list the CVE.")
                    Double epssPercentile,
            boolean isKev,
            String targetName,
            String targetKind,
            int priorityScore,
            String priorityTier,
            RecommendedAction recommendedAction) {

        public static EpssPrioritizedIssueView of(EpssPrioritizedIssue issue) {
            return new EpssPrioritizedIssueView(
                    issue.issueId(),
                    issue.identifier(),
                    issue.title(),
                    issue.severity(),
                    issue.cvssScore(),
                    issue.epssScore(),
                    issue.epssPercentile(),
                    issue.isKev(),
                    issue.targetName(),
                    issue.targetKind(),
                    issue.priorityScore(),
                    issue.priorityTier(),
                    issue.recommendedAction());
        }
    }
}
