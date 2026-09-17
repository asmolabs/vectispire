package com.asmolabs.vectispire.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ComplianceEngine regulatory assessment")
class ComplianceEngineTest {

    /** A clean fleet: nothing found anywhere. What the platform has switched on varies per test. */
    private static final ComplianceEngine.PostureInput CLEAN = new ComplianceEngine.PostureInput(
            10, 10, 10, 30, 10,
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
                10, 10, 10, 30, 10,
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
    @DisplayName("refuses to call an unscanned estate compliant, however clean its backlog looks")
    void anUnscannedEstateIsNotCompliant() {
        // Ten targets, not one of them ever observed, and therefore not one finding. This is the
        // shape a brand-new deployment has, and the shape an abandoned one drifts into — and the
        // assessment used to score it exactly like an estate that had been scanned and was clean.
        ComplianceEngine.PostureInput unobserved = new ComplianceEngine.PostureInput(
                10, 0, 0, 30, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                0,
                true);

        ComplianceEvaluation.ControlAssessment assessed = control(
                ComplianceEngine.evaluateAll(unobserved, ComplianceEngine.PlatformPosture.FULLY_ENABLED),
                ComplianceControl.Category.VULNERABILITY_MANAGEMENT);

        assertThat(assessed.status())
                .as("no findings because nobody looked is not the same fact as no findings")
                .isEqualTo(ComplianceControl.Status.NON_COMPLIANT);
        assertThat(assessed.details())
                .as("and the reader is told which part of the estate the verdict does not cover")
                .contains("never been scanned");
    }

    @Test
    @DisplayName("caps a stale estate at partial rather than failing it")
    void aStaleEstateIsCappedNotFailed() {
        // Everything was observed, none of it recently. That is a different failure from never
        // having looked: the estate was described once, and the description is out of date.
        ComplianceEngine.PostureInput stale = new ComplianceEngine.PostureInput(
                10, 10, 0, 30, 10,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                10,
                true);

        ComplianceEvaluation.ControlAssessment assessed = control(
                ComplianceEngine.evaluateAll(stale, ComplianceEngine.PlatformPosture.FULLY_ENABLED),
                ComplianceControl.Category.VULNERABILITY_MANAGEMENT);

        assertThat(assessed.status()).isEqualTo(ComplianceControl.Status.PARTIAL);
        assertThat(assessed.details()).contains("more than 30 days ago");
    }

    @Test
    @DisplayName("leaves a fully observed estate exactly as it was scored")
    void afullyObservedEstateIsUntouched() {
        ComplianceEvaluation.ControlAssessment assessed = control(
                ComplianceEngine.evaluateAll(CLEAN, ComplianceEngine.PlatformPosture.FULLY_ENABLED),
                ComplianceControl.Category.VULNERABILITY_MANAGEMENT);

        assertThat(assessed.status())
                .as("the cap must not touch the case the control was written for")
                .isEqualTo(ComplianceControl.Status.COMPLIANT);
        assertThat(assessed.details()).doesNotContain("Assessment covers");
    }

    @Test
    @DisplayName("marks non-compliant when critical issues, overdue SLA, or secrets are present")
    void nonCompliantState() {
        ComplianceEngine.PostureInput flawedPosture = new ComplianceEngine.PostureInput(
                10, 8, 8, 30, 5,
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
                new ComplianceEngine.PlatformPosture(false, false, true, true, true, false);

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
                new ComplianceEngine.PlatformPosture(true, true, false, true, true, false);

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
                new ComplianceEngine.PlatformPosture(true, true, true, false, true, false);

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
                10, 10, 10, 30, 10,
                0, 0, 0, 0, 0, 0, 8, 0, 0,
                10,
                true);

        var assessment = control(
                ComplianceEngine.evaluateAll(leaking, new ComplianceEngine.PlatformPosture(false, false, true, true, true, false)),
                ComplianceControl.Category.SECRETS_MANAGEMENT);

        assertThat(assessment.status()).isEqualTo(ComplianceControl.Status.NON_COMPLIANT);
        assertThat(assessment.scorePercentage()).isZero();
    }

    @Test
    @DisplayName("a local password with no provider caps accountability, whatever the chain says")
    void noProviderCapsAuditability() {
        ComplianceEngine.PlatformPosture passwordOnly =
                new ComplianceEngine.PlatformPosture(true, true, true, true, false, true);

        // **The hole this closes.** The posture had no opinion about authentication: a deployment
        // could be declared compliant with PCI DSS and SOC 2 — both of which require a second factor
        // — while accepting nothing but a local password. The audit chain proves an entry was not
        // altered; it does not prove that the name it carries is that of the person who acted.
        assertThat(auditControls(passwordOnly))
                .allSatisfy(control -> {
                    assertThat(control.status()).isNotEqualTo(ComplianceControl.Status.COMPLIANT);
                    assertThat(control.scorePercentage()).isLessThanOrEqualTo(65);
                    assertThat(control.details()).contains("no second factor");
                });
    }

    @Test
    @DisplayName("a provider beside an open password is better, and still not what it claims")
    void anOpenPasswordBesideAProviderIsStillABypass() {
        // The state that gets missed: the provider is there, and so is the door next to it. The
        // realm's second factor is bypassed through it.
        ComplianceEngine.PlatformPosture both =
                new ComplianceEngine.PlatformPosture(true, true, true, true, true, true);

        assertThat(auditControls(both))
                .allSatisfy(control -> {
                    assertThat(control.scorePercentage()).isLessThanOrEqualTo(85);
                    assertThat(control.details()).contains("walked around");
                });

        // And both doors set as the control describes: no ceiling.
        assertThat(auditControls(ComplianceEngine.PlatformPosture.FULLY_ENABLED))
                .allSatisfy(control -> assertThat(control.details()).doesNotContain("walked around"));
    }

    /** Every framework's logging controls, under a given posture. */
    private static java.util.List<ComplianceEvaluation.ControlAssessment> auditControls(
            ComplianceEngine.PlatformPosture platform) {
        return ComplianceEngine.evaluateAll(CLEAN, platform).stream()
                .flatMap(evaluation -> evaluation.controls().stream())
                .filter(control -> control.control().category() == ComplianceControl.Category.AUDIT_AND_LOGGING)
                .toList();
    }

}
