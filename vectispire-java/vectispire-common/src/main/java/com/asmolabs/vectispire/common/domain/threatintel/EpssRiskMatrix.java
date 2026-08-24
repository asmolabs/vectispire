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
            String recommendedAction) {}

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

    public static String determineAction(String tier, boolean isKev, String reachability) {
        return switch (tier) {
            case "CRITICAL_ARMED" -> isKev
                    ? "P0 - Remédiation sous 24h (Catalogue CISA KEV - Exploitation active confirmée)"
                    : "P0 - Remédiation sous 48h (Probabilité d'exploit critique > 50%)";
            case "HIGH_PROBABLE" -> "P1 - Remédiation prioritaire sous 7 jours (Armement probable)";
            case "MEDIUM_THEORETICAL" -> "P2 - Remédiation standard sous 30 jours (Sévérité haute mais exploit peu probable)";
            default -> "P3 - Traitement au fil de l'eau (Probabilité d'exploitation négligeable)";
        };
    }
}
