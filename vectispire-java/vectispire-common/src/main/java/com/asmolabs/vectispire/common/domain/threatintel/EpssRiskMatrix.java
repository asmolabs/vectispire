package com.asmolabs.vectispire.common.domain.threatintel;

import java.util.List;
import java.util.Map;

/**
 * Pure domain model for FIRST.org EPSS and CISA KEV exploitability prioritization.
 */
public final class EpssRiskMatrix {

    private EpssRiskMatrix() {}

    public record EpssPrioritizedIssue(
            Long issueId,
            String identifier,
            String title,
            String severity,
            Double cvssScore,
            Double epssScore,
            Double epssPercentile,
            boolean isKev,
            String reachability,
            String targetName,
            String targetKind,
            int priorityScore,
            String priorityTier,
            RecommendedAction recommendedAction) {}

    public record EpssFleetSummary(
            int totalVulnerabilities,
            int activeKevCount,
            int highEpssCount,
            int reachableEpssCount,
            double averageFleetEpss,
            List<EpssPrioritizedIssue> topPriorities,
            Map<String, Integer> breakdownByTier) {}

    public static int calculatePriorityScore(Double cvss, Double epss, boolean isKev, String reachability) {
        double cvssVal = cvss != null ? cvss : 5.0;
        double epssVal = epss != null ? epss : 0.01;
        boolean reachable = "REACHABLE".equalsIgnoreCase(reachability);

        // CVSS weight: up to 30 pts
        double cvssComponent = (cvssVal / 10.0) * 30.0;

        // EPSS weight: up to 40 pts
        double epssComponent = Math.min(40.0, epssVal * 40.0 * 2.0); // max reached at 0.50

        // KEV bonus: +30 pts
        double kevComponent = isKev ? 30.0 : 0.0;

        double baseScore = cvssComponent + epssComponent + kevComponent;

        // Reachability multiplier
        if (reachable) {
            baseScore *= 1.25;
        } else if ("UNREACHABLE".equalsIgnoreCase(reachability)) {
            baseScore *= 0.75;
        }

        return (int) Math.round(Math.min(100.0, Math.max(0.0, baseScore)));
    }

    public static String determineTier(Double cvss, Double epss, boolean isKev, String reachability) {
        double cvssVal = cvss != null ? cvss : 5.0;
        double epssVal = epss != null ? epss : 0.01;
        boolean reachable = "REACHABLE".equalsIgnoreCase(reachability);

        if (isKev || (epssVal >= 0.50 && cvssVal >= 7.0) || (epssVal >= 0.20 && reachable && cvssVal >= 7.0)) {
            return "CRITICAL_ARMED";
        }
        if (epssVal >= 0.20 || (epssVal >= 0.05 && cvssVal >= 7.0)) {
            return "HIGH_PROBABLE";
        }
        if (cvssVal >= 7.0 && epssVal < 0.05) {
            return "MEDIUM_THEORETICAL";
        }
        return "LOW_PROBABILITY";
    }

    /**
     * What to do about an issue, as a token the screen translates.
     *
     * <p><b>A token and not a sentence</b>, for the reason {@code RemediationGap} states: the
     * sentence is screen text, and screen text is translated on the client. This field used to
     * carry a French sentence that the EPSS screen printed as it stood — under a column header
     * that went through the translation bundle, so the heading changed language and the cell
     * below it did not.
     *
     * <p>An enum rather than a free string: springdoc enumerates it, so the document publishes
     * the five values and the generated client type is exactly this set. A renamed constant
     * fails the contract test rather than reaching a screen as an unresolved key.
     */
    public enum RecommendedAction {
        /** Actively exploited, per the CISA KEV catalogue. */
        P0_KEV_24H,
        /** Exploit probability above 50 %, with no KEV listing. */
        P0_48H,
        P1_7D,
        P2_30D,
        P3_ROUTINE
    }

    public static RecommendedAction determineAction(String tier, boolean isKev, String reachability) {
        return switch (tier) {
            case "CRITICAL_ARMED" -> isKev ? RecommendedAction.P0_KEV_24H : RecommendedAction.P0_48H;
            case "HIGH_PROBABLE" -> RecommendedAction.P1_7D;
            case "MEDIUM_THEORETICAL" -> RecommendedAction.P2_30D;
            default -> RecommendedAction.P3_ROUTINE;
        };
    }
}
