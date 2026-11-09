package com.asmolabs.vectispire.common.domain.remediation;

import java.util.List;

/**
 * A recommended remediation action that yields high security ROI by resolving multiple CVEs in one step.
 */
public record HighImpactFix(
        String packageName,
        String currentVersion,
        String recommendedVersion,
        long cveCountResolved,
        long criticalCveCount,
        long highCveCount,
        double estimatedHours,
        double leverageScore,
        List<String> affectedCves,
        List<String> affectedTargetNames) {}
