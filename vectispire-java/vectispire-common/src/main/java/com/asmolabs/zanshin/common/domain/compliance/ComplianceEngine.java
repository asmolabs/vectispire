package com.asmolabs.zanshin.common.domain.compliance;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure evaluation engine that assesses regulatory compliance from security state.
 */
public final class ComplianceEngine {

    private ComplianceEngine() {}

    /**
     * Aggregated security posture input for compliance assessment.
     */
    public record PostureInput(
            int totalTargets,
            int scannedTargets,
            int gatePassingTargets,
            long criticalIssues,
            long highIssues,
            long mediumIssues,
            long lowIssues,
            long kevIssues,
            long overdueIssues,
            long secretIssues,
            long sastIssues,
            long iacIssues,
            int targetsWithSbom,
            boolean auditChainValid) {}

    /**
     * Evaluates all supported regulatory frameworks.
     */
    public static List<ComplianceEvaluation> evaluateAll(PostureInput input) {
        List<ComplianceEvaluation> evaluations = new ArrayList<>();
        for (ComplianceFramework framework : ComplianceFramework.values()) {
            evaluations.add(evaluate(framework, input));
        }
        return List.copyOf(evaluations);
    }

    /**
     * Evaluates a single regulatory framework.
     */
    public static ComplianceEvaluation evaluate(ComplianceFramework framework, PostureInput input) {
        List<ComplianceEvaluation.ControlAssessment> assessments = new ArrayList<>();

        for (ComplianceControl control : framework.getControls()) {
            assessments.add(evaluateControl(control, input));
        }

        int totalScore = 0;
        int nonCompliantCount = 0;
        int partialCount = 0;

        for (ComplianceEvaluation.ControlAssessment assessment : assessments) {
            totalScore += assessment.scorePercentage();
            if (assessment.status() == ComplianceControl.Status.NON_COMPLIANT) {
                nonCompliantCount++;
            } else if (assessment.status() == ComplianceControl.Status.PARTIAL) {
                partialCount++;
            }
        }

        int overallScore = assessments.isEmpty() ? 100 : Math.round((float) totalScore / assessments.size());
        ComplianceControl.Status overallStatus;
        if (nonCompliantCount > 0 || overallScore < 70) {
            overallStatus = ComplianceControl.Status.NON_COMPLIANT;
        } else if (partialCount > 0 || overallScore < 95) {
            overallStatus = ComplianceControl.Status.PARTIAL;
        } else {
            overallStatus = ComplianceControl.Status.COMPLIANT;
        }

        return new ComplianceEvaluation(framework, overallScore, overallStatus, assessments);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateControl(ComplianceControl control, PostureInput input) {
        return switch (control.category()) {
            case VULNERABILITY_MANAGEMENT -> evaluateVulnerabilities(control, input);
            case SUPPLY_CHAIN -> evaluateSupplyChain(control, input);
            case SECRETS_MANAGEMENT -> evaluateSecrets(control, input);
            case SECURE_CODING -> evaluateSecureCoding(control, input);
            case INFRASTRUCTURE_AS_CODE -> evaluateIaC(control, input);
            case GOVERNANCE -> evaluateGovernance(control, input);
            case AUDIT_AND_LOGGING -> evaluateAudit(control, input);
        };
    }

    private static ComplianceEvaluation.ControlAssessment evaluateVulnerabilities(ComplianceControl control, PostureInput input) {
        int score = 100;
        List<String> notes = new ArrayList<>();
        List<String> guidance = new ArrayList<>();

        if (input.criticalIssues() > 0) {
            score -= Math.min(50, (int) input.criticalIssues() * 20);
            notes.add(input.criticalIssues() + " critical CVE(s) detected");
            guidance.add("Remediate or triage all critical CVEs immediately.");
        }
        if (input.kevIssues() > 0) {
            score -= Math.min(30, (int) input.kevIssues() * 15);
            notes.add(input.kevIssues() + " actively exploited CISA KEV vulnerability(ies)");
            guidance.add("Apply patches for CISA Known Exploited Vulnerabilities.");
        }
        if (input.overdueIssues() > 0) {
            score -= Math.min(40, (int) input.overdueIssues() * 10);
            notes.add(input.overdueIssues() + " vulnerability(ies) in SLA breach (overdue)");
            guidance.add("Resolve overdue findings to maintain compliance windows.");
        }
        if (input.highIssues() > 5) {
            score -= 10;
            notes.add(input.highIssues() + " high severity findings in backlog");
        }

        score = Math.max(0, score);
        ComplianceControl.Status status = statusForScore(score);
        String details = notes.isEmpty() ? "All vulnerabilities are within SLA thresholds with zero unmitigated criticals." : String.join(", ", notes) + ".";
        String remGuidance = guidance.isEmpty() ? "Maintain continuous vulnerability scanning and remediation cadence." : String.join(" ", guidance);

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, remGuidance);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateSupplyChain(ComplianceControl control, PostureInput input) {
        int total = Math.max(1, input.totalTargets());
        int withSbom = input.targetsWithSbom();
        int ratio = Math.round(((float) withSbom / total) * 100);

        int score = ratio;
        ComplianceControl.Status status = statusForScore(score);
        String details = withSbom + "/" + total + " monitored targets have an active Software Bill of Materials (SBOM).";
        String guidance = ratio < 100 ? "Execute Syft/Grype scans on all remaining targets to generate missing SBOMs." : "SBOM inventory is complete across all targets.";

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, guidance);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateSecrets(ComplianceControl control, PostureInput input) {
        long secrets = input.secretIssues();
        int score = secrets == 0 ? 100 : Math.max(0, 100 - (int) secrets * 25);
        ComplianceControl.Status status = secrets == 0 ? ComplianceControl.Status.COMPLIANT : ComplianceControl.Status.NON_COMPLIANT;
        String details = secrets == 0 ? "Zero exposed plaintext credentials or tokens detected." : secrets + " plaintext secret(s) or API key(s) detected in source code.";
        String guidance = secrets == 0 ? "Maintain automated Gitleaks pre-commit and pipeline verification." : "Rotate all leaked secrets immediately and purge from Git history.";

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, guidance);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateSecureCoding(ComplianceControl control, PostureInput input) {
        long sast = input.sastIssues();
        int score = sast == 0 ? 100 : Math.max(20, 100 - (int) sast * 5);
        ComplianceControl.Status status = statusForScore(score);
        String details = sast == 0 ? "No high-severity static analysis (SAST) flaws identified." : sast + " code quality / SAST finding(s) detected by Semgrep.";
        String guidance = sast == 0 ? "Continue enforcing automated Semgrep rules in development pipelines." : "Remediate static analysis findings in custom application code.";

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, guidance);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateIaC(ComplianceControl control, PostureInput input) {
        long iac = input.iacIssues();
        int score = iac == 0 ? 100 : Math.max(30, 100 - (int) iac * 10);
        ComplianceControl.Status status = statusForScore(score);
        String details = iac == 0 ? "Infrastructure-as-Code manifests conform to security baselines." : iac + " IaC security misconfiguration(s) detected by Checkov.";
        String guidance = iac == 0 ? "Keep IaC configurations locked to CIS security baselines." : "Remediate Terraform / Kubernetes / Dockerfile misconfigurations.";

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, guidance);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateGovernance(ComplianceControl control, PostureInput input) {
        int total = Math.max(1, input.totalTargets());
        int passing = input.gatePassingTargets();
        int score = Math.round(((float) passing / total) * 100);
        ComplianceControl.Status status = statusForScore(score);
        String details = passing + "/" + total + " monitored targets pass active Gate release policies.";
        String guidance = score < 100 ? "Resolve blocking gate violations before deploying targets to production." : "All targets currently satisfy gate security policies.";

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, guidance);
    }

    private static ComplianceEvaluation.ControlAssessment evaluateAudit(ComplianceControl control, PostureInput input) {
        int score = input.auditChainValid() ? 100 : 0;
        ComplianceControl.Status status = input.auditChainValid() ? ComplianceControl.Status.COMPLIANT : ComplianceControl.Status.NON_COMPLIANT;
        String details = input.auditChainValid() ? "Cryptographic HMAC audit chain integrity is verified and intact." : "Audit log integrity check failed or tampering detected.";
        String guidance = input.auditChainValid() ? "Audit logs are continuously sealed and tamper-evident." : "Investigate audit log integrity anomaly immediately.";

        return new ComplianceEvaluation.ControlAssessment(control, status, score, details, guidance);
    }

    private static ComplianceControl.Status statusForScore(int score) {
        if (score >= 90) return ComplianceControl.Status.COMPLIANT;
        if (score >= 60) return ComplianceControl.Status.PARTIAL;
        return ComplianceControl.Status.NON_COMPLIANT;
    }
}
