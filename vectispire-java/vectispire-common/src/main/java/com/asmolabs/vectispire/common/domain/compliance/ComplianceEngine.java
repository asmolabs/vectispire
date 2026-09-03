package com.asmolabs.vectispire.common.domain.compliance;

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
     * What the control plane has switched on, as opposed to what it found in the fleet.
     *
     * <p><b>Why this is a second input and not four more fields.</b> Everything in
     * {@link PostureInput} is a measurement of somebody else's code. Everything here is a
     * property of <em>this</em> deployment: whether it can encrypt what it stores, whether its
     * audit log has a second copy, whether it requires two people to grant an exemption. They are
     * different kinds of evidence and an assessor treats them differently — the first is a
     * finding, the second is a control.
     *
     * <p><b>The defect this closes.</b> The engine scored the fleet and never looked at the
     * platform. An instance running with no encryption key at all — deployment SSH keys it cannot
     * protect — scored 100/100 on "Access Control &amp; Secret Leakage Prevention", because the
     * only thing that control counted was how many secrets Gitleaks found in the repositories it
     * scanned. That is the same criticism this project makes of a CI pipeline that reports other
     * people's vulnerable dependencies and never looks at its own.
     *
     * @param encryptionConfigured a key is present, so a secret stored here can actually be
     *     encrypted. Without it the application still reads what it already holds and refuses new
     *     writes — which is why the absence is quiet and has to be reported here
     * @param externalKms key custody is Vault Transit rather than a local derivation. Not required
     *     by any control below, but it is what separates "encrypted" from "encrypted with a key
     *     held on the same host"
     * @param auditMirrorConfigured the audit log has a second copy outside the database. **The
     *     chain alone cannot detect the deletion of an entry nobody descends from** — the last one
     *     written, which is precisely the one an attacker wants gone. The mirror is what closes
     *     that, and an instance without one has an audit trail weaker than its score suggests
     * @param fourEyesRequired an exemption raised by a developer needs a second person. Off, the
     *     gate is advisory: whoever finds a vulnerability can dismiss it
     * @param singleSignOnConfigured an identity provider vouches for who is signing in. **The audit
     *     chain proves an entry was not altered; it does not prove the name on it.** That name is
     *     only worth what the sign-in behind it was worth, and this posture had no opinion on
     *     authentication at all — so a deployment could be reported compliant against PCI DSS and
     *     SOC 2, both of which require a second factor, while accepting a password and nothing else
     * @param passwordLoginOpen a local password is still exchangeable for a session. Beside a
     *     configured provider this is not neutral: it is a way around whatever second factor the
     *     realm enforces, which is the reason {@code VECTISPIRE_PASSWORD_LOGIN=false} exists
     */
    public record PlatformPosture(
            boolean encryptionConfigured,
            boolean externalKms,
            boolean auditMirrorConfigured,
            boolean fourEyesRequired,
            boolean singleSignOnConfigured,
            boolean passwordLoginOpen) {

        /**
         * Everything on. Named rather than written as four literals so a test that does not care
         * about the platform says so, and a test that does care is impossible to misread.
         */
        public static final PlatformPosture FULLY_ENABLED =
                new PlatformPosture(true, true, true, true, true, false);
    }

    /**
     * Evaluates all supported regulatory frameworks.
     */
    public static List<ComplianceEvaluation> evaluateAll(PostureInput input, PlatformPosture platform) {
        List<ComplianceEvaluation> evaluations = new ArrayList<>();
        for (ComplianceFramework framework : ComplianceFramework.values()) {
            evaluations.add(evaluate(framework, input, platform));
        }
        return List.copyOf(evaluations);
    }

    /**
     * Evaluates a single regulatory framework.
     */
    public static ComplianceEvaluation evaluate(
            ComplianceFramework framework, PostureInput input, PlatformPosture platform) {
        List<ComplianceEvaluation.ControlAssessment> assessments = new ArrayList<>();

        for (ComplianceControl control : framework.getControls()) {
            assessments.add(cappedByPlatform(evaluateControl(control, input), platform));
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

    /**
     * Lowers an assessment when the platform capability the control rests on is switched off.
     *
     * <p><b>A cap, not a penalty.</b> The finding-based score keeps its meaning — zero leaked
     * secrets is still zero leaked secrets — but a control cannot be reported <em>compliant</em>
     * on the strength of evidence that does not cover it. The ceiling is deliberately generous:
     * the point is to stop the green tick, not to invent a number.
     *
     * <p><b>Why this is worth the noise it creates.</b> A compliance report is read by somebody
     * who will sign something on the strength of it. "Compliant" against a control whose
     * mechanism is off is worse than no report at all — it is the reader's own diligence,
     * returned to them as a conclusion. Every cap below therefore says which switch to flip.
     */
    private static ComplianceEvaluation.ControlAssessment cappedByPlatform(
            ComplianceEvaluation.ControlAssessment assessment, PlatformPosture platform) {

        return switch (assessment.control().category()) {
            case SECRETS_MANAGEMENT -> platform.encryptionConfigured()
                    ? assessment
                    : capped(assessment, 60,
                            "No encryption key is configured, so secrets stored by Vectispire itself "
                                    + "(deployment SSH keys, integration tokens) cannot be encrypted at rest — "
                                    + "this control counts only what was found in the scanned repositories",
                            "Set ENCRYPTION_KEY (or ENCRYPTION_KEY_FILE) and re-save the stored credentials.");

            // **Deux plafonds ici, et le second porte sur l'identité.** Le premier tient à ce que
            // la chaîne ne peut pas prouver d'elle-même — qu'aucune entrée n'a été supprimée. Le
            // second tient à ce qu'elle ne prouve pas non plus : que le nom porté par une entrée
            // est celui de la personne qui a agi. Une chaîne intacte au-dessus d'un mot de passe
            // partageable est une traçabilité plus faible que son score.
            case AUDIT_AND_LOGGING -> authenticationCap(platform.auditMirrorConfigured()
                    ? assessment
                    : capped(assessment, 70,
                            "No audit mirror is configured. The hash chain makes a modified entry detectable, "
                                    + "but it cannot detect the deletion of an entry nobody descends from — "
                                    + "the last one written, which is the one an attacker removes",
                            "Configure vectispire.audit.mirror-path and ship the file off the host, so the "
                                    + "deletion has to be performed twice in two media."), platform);

            case GOVERNANCE -> platform.fourEyesRequired()
                    ? assessment
                    : capped(assessment, 75,
                            "Four-eyes approval is disabled, so the account that raises an exemption can also "
                                    + "grant it — the gate verdict below is advisory rather than enforced",
                            "Enable triage_four_eyes_required so a dismissal needs a second person.");

            default -> assessment;
        };
    }

    /**
     * The ceiling that identity puts on accountability.
     *
     * <p>Three states, and the middle one is the one people miss. No provider at all is the
     * weakest: whoever signs the report is vouching for a local password with no second factor.
     * A provider <em>beside</em> an open password is better and still not what it claims — the
     * realm's second factor is bypassable by the door next to it, which is the whole reason
     * {@code VECTISPIRE_PASSWORD_LOGIN=false} exists. Both doors closed but one is the state the
     * control describes, and it is left alone.
     */
    private static ComplianceEvaluation.ControlAssessment authenticationCap(
            ComplianceEvaluation.ControlAssessment assessment, PlatformPosture platform) {

        if (!platform.singleSignOnConfigured()) {
            return capped(assessment, 65,
                    "No identity provider is configured, so every account signs in with a local "
                            + "password and no second factor. The audit chain proves an entry was not "
                            + "altered; it cannot prove the name on it belongs to the person who acted",
                    "Set VECTISPIRE_OIDC_ISSUER so the organisation's own authentication policy — "
                            + "including its second factor — stands behind every entry in this log.");
        }
        if (platform.passwordLoginOpen()) {
            return capped(assessment, 85,
                    "An identity provider is configured, and local password sign-in is still open "
                            + "beside it. Whatever second factor the realm enforces can be walked "
                            + "around through the other door",
                    "Set VECTISPIRE_PASSWORD_LOGIN=false once single sign-on is verified working. "
                            + "It is refused, loudly, while no provider is configured.");
        }
        return assessment;
    }

    /** Keeps the lower of the two scores, and never reports better than PARTIAL. */
    private static ComplianceEvaluation.ControlAssessment capped(
            ComplianceEvaluation.ControlAssessment assessment, int ceiling, String why, String how) {

        int score = Math.min(assessment.scorePercentage(), ceiling);
        ComplianceControl.Status status = assessment.status() == ComplianceControl.Status.NON_COMPLIANT
                ? ComplianceControl.Status.NON_COMPLIANT
                : ComplianceControl.Status.PARTIAL;

        return new ComplianceEvaluation.ControlAssessment(
                assessment.control(),
                status,
                score,
                assessment.details() + " " + why + ".",
                why.isEmpty() ? assessment.remediationGuidance() : how + " " + assessment.remediationGuidance());
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
