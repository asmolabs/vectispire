package com.asmolabs.vectispire.core.posture.web;

import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * The security debt report, as the wire carries it — the domain record field for field, published
 * under the same schema names, with the one claim the domain module cannot write down.
 *
 * <h2>Why a view</h2>
 *
 * <p><b>{@code recommendedVersion} is null when no finding announces a fix</b>
 * ({@code SecurityDebtService.rank}: "no fixed version published" is an answer). The document said
 * {@code string}, as it does of every reference field it knows nothing about, and the client took
 * the hint: {@code api.models.ts} claimed the field non-null, the dashboard printed
 * {@code 2.14.1 ➔ } with nothing after the arrow, and the one spec that sent the null had to cast
 * it through {@code unknown} to get past its own type. The claim belongs in the contract, so the
 * generated type says {@code string | null} without anyone having to remember.
 *
 * <p>{@code vectispire-common} depends on no web annotation, so {@code @Schema} cannot sit on
 * {@link HighImpactFix} — the reason {@link RemediationDistributionView} gives too. The names stay
 * {@code SecurityDebtReport} and {@code HighImpactFix}: the client reads both schemas by name.
 *
 * <p>Every other field of a fix is never null: the package name is the group's key and the query
 * keeps packaged findings only, the current version falls back to {@code "various"}, and both lists
 * are copies.
 */
@Schema(name = "SecurityDebtReport")
public record SecurityDebtReportView(
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
        List<HighImpactFixView> topHighImpactFixes) {

    public static SecurityDebtReportView of(SecurityDebtReport report) {
        return new SecurityDebtReportView(
                report.totalOpenIssues(),
                report.criticalIssues(),
                report.highIssues(),
                report.mediumIssues(),
                report.lowIssues(),
                report.totalEstimatedHours(),
                report.totalEstimatedPersonDays(),
                report.vulnerabilitiesDebtHours(),
                report.secretsDebtHours(),
                report.sastDebtHours(),
                report.iacDebtHours(),
                report.licenseDebtHours(),
                report.eolDebtHours(),
                report.topHighImpactFixes().stream().map(HighImpactFixView::of).toList());
    }

    /** @see HighImpactFix */
    @Schema(name = "HighImpactFix")
    public record HighImpactFixView(
            String packageName,
            String currentVersion,
            @Schema(types = {"string", "null"}, description = "The highest version the findings say fixes it; null when none announces a fix.")
                    String recommendedVersion,
            long cveCountResolved,
            long criticalCveCount,
            long highCveCount,
            double estimatedHours,
            double leverageScore,
            List<String> affectedCves,
            List<String> affectedTargetNames) {

        public static HighImpactFixView of(HighImpactFix fix) {
            return new HighImpactFixView(
                    fix.packageName(),
                    fix.currentVersion(),
                    fix.recommendedVersion(),
                    fix.cveCountResolved(),
                    fix.criticalCveCount(),
                    fix.highCveCount(),
                    fix.estimatedHours(),
                    fix.leverageScore(),
                    fix.affectedCves(),
                    fix.affectedTargetNames());
        }
    }
}
