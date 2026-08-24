package com.asmolabs.vectispire.common.domain.remediation;

import java.util.List;

/**
 * Quantifies engineering security debt and remediation effort across an organization's backlog.
 */
public record SecurityDebtReport(
        long totalOpenIssues,
        long criticalIssues,
        long highIssues,
        long mediumIssues,
        long lowIssues,
        double totalEstimatedHours,
        double totalEstimatedPersonDays,
        double vulnerabilitiesDebtHours,
        double secretsDebtHours,
        double sastDebtHours,
        double iacDebtHours,
        List<HighImpactFix> topHighImpactFixes) {}
