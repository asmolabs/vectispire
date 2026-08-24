package com.asmolabs.vectispire.common.domain.licenses;

/**
 * A single software dependency license observation in a target.
 */
public record LicenseEntry(
        String packageName,
        String packageVersion,
        String purl,
        String license,
        LicenseRiskCategory riskCategory,
        boolean compliant,
        String violationReason,
        Long targetId,
        String targetKind,
        String targetName) {}
