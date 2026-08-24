package com.asmolabs.vectispire.common.domain.sbom;

import java.util.List;

/**
 * Full differential comparison report between two SBOM scans.
 */
public record SbomDiffReport(
        Long fromScanId,
        Long toScanId,
        String fromVersion,
        String toVersion,
        int addedCount,
        int removedCount,
        int versionChangedCount,
        int licenseChangedCount,
        int introducedCveCount,
        int resolvedCveCount,
        List<ComponentDelta> componentDeltas,
        List<CveDelta> cveDeltas) {}
