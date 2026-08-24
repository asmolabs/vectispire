package com.asmolabs.vectispire.common.domain.ticketing;

import com.asmolabs.vectispire.common.domain.issues.Severity;

/**
 * Pure generator of issue descriptions formatted for Jira, GitHub, and GitLab.
 */
public final class TicketDescription {

    private TicketDescription() {}

    public record IssueContext(
            String title,
            String ruleId,
            Severity severity,
            String component,
            String version,
            String targetName,
            String primaryLocation,
            Double cvssScore,
            String cve,
            String cwe,
            String description,
            String remediation,
            String vectispireUrl) {}

    public static String formatTitle(IssueContext ctx) {
        String prefix = ctx.severity() != null ? "[" + ctx.severity().name() + "] " : "";
        String cvePrefix = ctx.cve() != null && !ctx.cve().isBlank() ? ctx.cve() + " — " : "";
        return prefix + cvePrefix + (ctx.title() != null ? ctx.title() : ctx.ruleId());
    }

    public static String formatMarkdown(IssueContext ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Security Finding: ").append(ctx.title() != null ? ctx.title() : ctx.ruleId()).append("\n\n");
        sb.append("| Property | Value |\n");
        sb.append("|---|---|\n");
        sb.append("| **Severity** | `").append(ctx.severity() != null ? ctx.severity().name() : "UNKNOWN").append("` |\n");
        if (ctx.cvssScore() != null) {
            sb.append("| **CVSS Score** | ").append(ctx.cvssScore()).append(" |\n");
        }
        if (ctx.cve() != null && !ctx.cve().isBlank()) {
            sb.append("| **CVE** | [").append(ctx.cve()).append("](https://nvd.nist.gov/vuln/detail/").append(ctx.cve()).append(") |\n");
        }
        if (ctx.cwe() != null && !ctx.cwe().isBlank()) {
            sb.append("| **CWE** | ").append(ctx.cwe()).append(" |\n");
        }
        sb.append("| **Target** | `").append(ctx.targetName()).append("` |\n");
        if (ctx.component() != null) {
            sb.append("| **Component** | `").append(ctx.component()).append(ctx.version() != null ? "@" + ctx.version() : "").append("` |\n");
        }
        if (ctx.primaryLocation() != null) {
            sb.append("| **Location** | `").append(ctx.primaryLocation()).append("` |\n");
        }
        sb.append("\n");

        if (ctx.description() != null && !ctx.description().isBlank()) {
            sb.append("### Description\n\n").append(ctx.description()).append("\n\n");
        }

        if (ctx.remediation() != null && !ctx.remediation().isBlank()) {
            sb.append("### Recommended Remediation\n\n").append(ctx.remediation()).append("\n\n");
        }

        if (ctx.vectispireUrl() != null && !ctx.vectispireUrl().isBlank()) {
            sb.append("---\n*Tracked and managed by [Vectispire ASPM](").append(ctx.vectispireUrl()).append(")*\n");
        }

        return sb.toString();
    }
}
