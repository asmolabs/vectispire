package com.asmolabs.vectispire.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ComplianceEngine regulatory assessment")
class ComplianceEngineTest {

    /** A clean fleet: nothing found anywhere. What the platform has switched on varies per test. */
    private static final ComplianceEngine.PostureInput CLEAN = new ComplianceEngine.PostureInput(
            10, 10, 10,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
            10,
            true);

    private static ComplianceEvaluation.ControlAssessment control(
            List<ComplianceEvaluation> results, ComplianceControl.Category category) {
        return results.stream()
                .flatMap(e -> e.controls().stream())
                .filter(c -> c.control().category() == category)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no control in category " + category));
    }

    @Test
    @DisplayName("evaluates 100% compliant when security posture is clean")
    void perfectCompliance() {
        ComplianceEngine.PostureInput cleanPosture = new ComplianceEngine.PostureInput(
                10, 10, 10,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                10,
                true);

        List<ComplianceEvaluation> results = ComplianceEngine.evaluateAll(cleanPosture, ComplianceEngine.PlatformPosture.FULLY_ENABLED);

        assertThat(results).hasSize(6);
        for (ComplianceEvaluation eval : results) {
            assertThat(eval.overallStatus()).isEqualTo(ComplianceControl.Status.COMPLIANT);
            assertThat(eval.scorePercentage()).isEqualTo(100);
            assertThat(eval.controls()).allMatch(c -> c.status() == ComplianceControl.Status.COMPLIANT);
        }
    }

    @Test
    @DisplayName("marks non-compliant when critical issues, overdue SLA, or secrets are present")
    void nonCompliantState() {
        ComplianceEngine.PostureInput flawedPosture = new ComplianceEngine.PostureInput(
                10, 8, 5,
                3, 10, 15, 20, 2, 4, 2, 5, 3,
                5,
                true);

        List<ComplianceEvaluation> results = ComplianceEngine.evaluateAll(flawedPosture, ComplianceEngine.PlatformPosture.FULLY_ENABLED);

        assertThat(results).hasSize(6);
        for (ComplianceEvaluation eval : results) {
            assertThat(eval.scorePercentage()).isLessThan(70);
            assertThat(eval.overallStatus()).isEqualTo(ComplianceControl.Status.NON_COMPLIANT);
        }
    }

    @Test
    @DisplayName("a clean fleet is not compliant on secrets when the platform cannot encrypt its own")
    void secretsControlDependsOnEncryptionBeingConfigured() {
        // **The defect this pins.** The control counted only what Gitleaks found in the scanned
        // repositories, so an instance holding deployment SSH keys it cannot encrypt — no key
        // configured at all — reported "Zero exposed plaintext credentials" and scored 100. The
        // finding was true and the conclusion was not.
        ComplianceEngine.PlatformPosture noKey =
                new ComplianceEngine.PlatformPosture(false, false, true, true);

        var assessment = control(
                ComplianceEngine.evaluateAll(CLEAN, noKey),
                ComplianceControl.Category.SECRETS_MANAGEMENT);

        assertThat(assessment.status())
                .as("a control whose mechanism is off must not read as satisfied")
                .isEqualTo(ComplianceControl.Status.PARTIAL);
        assertThat(assessment.scorePercentage()).isLessThanOrEqualTo(60);
        assertThat(assessment.details()).contains("No encryption key is configured");
        assertThat(assessment.remediationGuidance()).contains("ENCRYPTION_KEY");
    }

    @Test
    @DisplayName("a valid chain is not a complete audit trail without a mirror, and says so")
    void auditControlDependsOnTheMirror() {
        // The property `AuditChain` documents about itself and the compliance report never
        // repeated: a valid chain detects a *modified* entry, and cannot detect the deletion of
        // one nobody descends from — the last one written. An assessor who finds that out
        // themselves discounts everything else in the report.
        ComplianceEngine.PlatformPosture noMirror =
                new ComplianceEngine.PlatformPosture(true, true, false, true);

        var assessment = control(
                ComplianceEngine.evaluateAll(CLEAN, noMirror),
                ComplianceControl.Category.AUDIT_AND_LOGGING);

        assertThat(assessment.status()).isEqualTo(ComplianceControl.Status.PARTIAL);
        assertThat(assessment.scorePercentage()).isLessThanOrEqualTo(70);
        assertThat(assessment.details())
                .contains("cannot detect the deletion of an entry nobody descends from");
    }

    @Test
    @DisplayName("governance is not satisfied by passing gates alone when four-eyes is off")
    void governanceControlDependsOnFourEyes() {
        ComplianceEngine.PlatformPosture noFourEyes =
                new ComplianceEngine.PlatformPosture(true, true, true, false);

        var assessment = control(
                ComplianceEngine.evaluateAll(CLEAN, noFourEyes),
                ComplianceControl.Category.GOVERNANCE);

        assertThat(assessment.status()).isEqualTo(ComplianceControl.Status.PARTIAL);
        assertThat(assessment.scorePercentage()).isLessThanOrEqualTo(75);
        assertThat(assessment.details()).contains("Four-eyes approval is disabled");
    }

    @Test
    @DisplayName("a cap lowers a passing control and never raises a failing one")
    void aCapNeverImprovesAnAssessment() {
        // The cap exists to stop a green tick, not to invent a number. A control already failing
        // on findings must keep saying so — reporting it as PARTIAL because a switch is off would
        // be an improvement earned by a second defect.
        ComplianceEngine.PostureInput leaking = new ComplianceEngine.PostureInput(
                10, 10, 10,
                0, 0, 0, 0, 0, 0, 8, 0, 0,
                10,
                true);

        var assessment = control(
                ComplianceEngine.evaluateAll(leaking, new ComplianceEngine.PlatformPosture(false, false, true, true)),
                ComplianceControl.Category.SECRETS_MANAGEMENT);

        assertThat(assessment.status()).isEqualTo(ComplianceControl.Status.NON_COMPLIANT);
        assertThat(assessment.scorePercentage()).isZero();
    }
}
