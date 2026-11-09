package com.asmolabs.vectispire.common.domain.remediation;

import java.util.List;

/**
 * Quantifies engineering security debt and remediation effort across an organization's backlog.
 *
 * <p><b>The buckets sum to the total, and everything counted lands in one.</b> That identity used
 * to be false: the estimate covered four of the eight finding types, so a critical SAST finding
 * appeared in {@code criticalIssues} and in no bucket — counted as urgent and free to fix. The
 * two fields at the end of the list exist because closing that gap needs somewhere to put the
 * hours, not because anyone asked for more numbers.
 *
 * @param sastDebtHours source-code findings, security and quality alike. Named for the first and
 *     fed by both, which is a compromise: they are the same edit-and-retest loop, and splitting
 *     them would put a number on a screen that nobody reads differently
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
        double licenseDebtHours,
        double eolDebtHours,
        List<HighImpactFix> topHighImpactFixes) {}
