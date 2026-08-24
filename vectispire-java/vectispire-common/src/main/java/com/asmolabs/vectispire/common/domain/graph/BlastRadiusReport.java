package com.asmolabs.vectispire.common.domain.graph;

import java.util.List;

/**
 * Detailed organizational impact assessment and blast radius report for a given package or CVE.
 */
public record BlastRadiusReport(
        String query,
        String queryType, // "PACKAGE" or "CVE"
        int totalTargetsAffected,
        int directUsages,
        int transitiveUsages,
        int totalAssociatedCves,
        int blastRadiusScore, // 0 - 100
        List<TargetImpact> targets,
        DependencyGraph graph) {

    public record TargetImpact(
            Long targetId,
            String targetKind, // "REPOSITORY" or "CONTAINER"
            String targetName,
            String targetContext, // Branch or Image tag
            String sourceFile, // Manifest or binary path
            String purl,
            String packageName,
            String packageVersion,
            boolean isDirect,
            List<String> cves,
            String reachability,
            Long scanId) {}

    public record TopImpactPackage(
            String packageName,
            String ecosystem,
            int affectedTargetsCount,
            int directUsages,
            int transitiveUsages,
            int totalCves,
            double maxCvss,
            int blastRadiusScore) {}

    /**
     * Computes an organizational Blast Radius Risk Score between 0 and 100 based on target dispersion,
     * direct vs transitive exposure, reachability, and severity.
     */
    public static int calculateScore(int targetsCount, int directCount, int transitiveCount, int cveCount, double maxCvss) {
        if (targetsCount == 0) {
            return 0;
        }

        // Target reach weight (up to 40 pts)
        double dispersionWeight = Math.min(40.0, targetsCount * 8.0);

        // Direct exposure weight (up to 20 pts)
        double directWeight = Math.min(20.0, directCount * 10.0 + transitiveCount * 2.0);

        // CVSS Severity weight (up to 40 pts)
        double severityWeight = (maxCvss / 10.0) * 40.0;

        return (int) Math.round(Math.min(100.0, dispersionWeight + directWeight + severityWeight));
    }
}
