package com.asmolabs.zanshin.common.domain.licenses;

import java.util.Map;

/**
 * Aggregate summary metrics of open source software licenses across targets.
 */
public record LicenseSummary(
        long totalDependencies,
        long uniqueLicenses,
        long nonCompliantCount,
        Map<LicenseRiskCategory, Long> breakdownByRisk) {}
