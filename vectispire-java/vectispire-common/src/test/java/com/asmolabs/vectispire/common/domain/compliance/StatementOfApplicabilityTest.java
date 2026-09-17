package com.asmolabs.vectispire.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Applicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Divergence;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.EvidenceSource;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Implementation;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Line;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.SoaStatement;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Setting what was declared against what was measured.
 *
 * <p><b>The suite is about the disagreements, because the agreements were never the point.</b>
 * Either half of this feature is easy and useless alone: a stored document nobody checks, or a
 * measurement nobody claimed anything about. What an assessment turns on is the line where the
 * two differ, and each of those lines means something different — being short of a control, and
 * having said in writing that you were not, are two findings and only one of them is about the
 * estate.
 */
@DisplayName("the declaration of applicability")
class StatementOfApplicabilityTest {

    private static final Instant NOW = Instant.parse("2026-09-14T10:00:00Z");
    private static final ComplianceFramework FRAMEWORK = ComplianceFramework.ISO_27001;

    /** La même, telle que la déclaration la range — une chaîne, depuis que le Top 10 s'y déclare. */
    private static final String FRAMEWORK_KEY = FRAMEWORK.name();
    private static final String VULN = "ISO-A.8.8";
    private static final String SECRETS = "ISO-A.5.15";

    @Test
    @DisplayName("reports a control declared implemented and measured non-compliant as the finding")
    void contradictionIsTheFinding() {
        SoaStatement statement = reconcile(
                List.of(declared(VULN, Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE)),
                measured(VULN, ComplianceControl.Status.NON_COMPLIANT));

        assertThat(divergenceOf(statement, VULN))
                .as("the organisation is not merely short of the control, it said otherwise in writing")
                .isEqualTo(Divergence.CONTRADICTED);
        assertThat(Divergence.CONTRADICTED.isFinding()).isTrue();
        assertThat(statement.findings()).isPositive();
    }

    @Test
    @DisplayName("calls a control declared implemented and measured partial overstated, not contradicted")
    void partialIsOverstatedNotContradicted() {
        SoaStatement statement = reconcile(
                List.of(declared(VULN, Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE)),
                measured(VULN, ComplianceControl.Status.PARTIAL));

        assertThat(divergenceOf(statement, VULN)).isEqualTo(Divergence.OVERSTATED);
        assertThat(Divergence.OVERSTATED.isFinding())
                .as("a document ahead of the practice is not the same class of problem as a false claim")
                .isFalse();
    }

    @Test
    @DisplayName("declines to judge a control whose evidence lives somewhere else")
    void externalEvidenceIsNotJudged() {
        Declaration elsewhere = new Declaration(
                FRAMEWORK_KEY, SECRETS, Applicability.APPLICABLE, "Access control is run by IAM.",
                Implementation.IMPLEMENTED, EvidenceSource.EXTERNAL, "IAM quarterly access review, ref AR-2026-Q2",
                "n.faure", "c.moreau", NOW, NOW, NOW.plusSeconds(86_400));

        SoaStatement statement =
                reconcile(List.of(elsewhere), measured(SECRETS, ComplianceControl.Status.NON_COMPLIANT));

        assertThat(divergenceOf(statement, SECRETS))
                .as("a secret scanner's opinion is not a verdict on the whole of access control")
                .isEqualTo(Divergence.NOT_MEASURED_HERE);
        // The framework's other three controls are undeclared here, and those are findings.
        // What must not appear among them is this line.
        assertThat(statement.lines())
                .as("manufacturing this finding would make every other one untrustworthy")
                .filteredOn(line -> line.divergence().isFinding())
                .extracting(line -> line.control().id())
                .doesNotContain(SECRETS);
    }

    @Test
    @DisplayName("judges a control evidenced both here and elsewhere, on the part measured here")
    void bothIsStillJudged() {
        Declaration both = new Declaration(
                FRAMEWORK_KEY, VULN, Applicability.APPLICABLE, "Scanning here, patching in the change process.",
                Implementation.IMPLEMENTED, EvidenceSource.BOTH, "Change management CAB minutes",
                "n.faure", "c.moreau", NOW, NOW, NOW.plusSeconds(86_400));

        assertThat(divergenceOf(
                        reconcile(List.of(both), measured(VULN, ComplianceControl.Status.NON_COMPLIANT)), VULN))
                .as("the slice measured here is non-compliant, and that slice was claimed implemented")
                .isEqualTo(Divergence.CONTRADICTED);
    }

    @Test
    @DisplayName("raises an exclusion carrying no justification")
    void exclusionNeedsAJustification() {
        Declaration bare = new Declaration(
                FRAMEWORK_KEY, VULN, Applicability.EXCLUDED, "  ", null,
                EvidenceSource.EXTERNAL, null, "n.faure", "c.moreau", NOW, NOW, null);

        SoaStatement statement = reconcile(List.of(bare), measured(VULN, ComplianceControl.Status.COMPLIANT));

        assertThat(divergenceOf(statement, VULN))
                .as("clause 6.1.3 d allows an exclusion and requires it to be argued")
                .isEqualTo(Divergence.EXCLUDED_WITHOUT_JUSTIFICATION);
        assertThat(statement.findings()).isPositive();
    }

    @Test
    @DisplayName("stops at the exclusion, whatever the estate happens to measure")
    void exclusionEndsTheQuestion() {
        Declaration excluded = new Declaration(
                FRAMEWORK_KEY, VULN, Applicability.EXCLUDED, "No development in the certified scope.",
                null, EvidenceSource.EXTERNAL, null, "n.faure", "c.moreau", NOW, NOW, null);

        assertThat(divergenceOf(
                        reconcile(List.of(excluded), measured(VULN, ComplianceControl.Status.NON_COMPLIANT)), VULN))
                .isEqualTo(Divergence.NOT_APPLICABLE);
    }

    @Test
    @DisplayName("shows a control nobody addressed rather than leaving it out")
    void undeclaredControlsAreShown() {
        SoaStatement statement = reconcile(List.of(), measured(VULN, ComplianceControl.Status.COMPLIANT));

        assertThat(statement.lines())
                .as("driven by the framework, so an unaddressed control cannot disappear")
                .hasSize(FRAMEWORK.getControls().size());
        assertThat(statement.lines()).allSatisfy(line ->
                assertThat(line.divergence()).isEqualTo(Divergence.UNDECLARED));
        assertThat(statement.complete()).isFalse();
        assertThat(statement.declared()).isZero();
        assertThat(statement.findings()).isEqualTo(FRAMEWORK.getControls().size());
    }

    @Test
    @DisplayName("is complete only when every control is addressed")
    void completeMeansEveryControl() {
        List<Declaration> all = FRAMEWORK.getControls().stream()
                .map(control -> declared(control.id(), Implementation.IMPLEMENTED, EvidenceSource.EXTERNAL))
                .toList();

        SoaStatement statement = reconcile(all, measured(VULN, ComplianceControl.Status.COMPLIANT));

        assertThat(statement.complete()).isTrue();
        assertThat(statement.declared()).isEqualTo(statement.total());
        assertThat(statement.findings()).isZero();
    }

    @Test
    @DisplayName("flags a document that has drifted behind the practice")
    void understatedIsReported() {
        assertThat(divergenceOf(
                        reconcile(
                                List.of(declared(VULN, Implementation.PLANNED, EvidenceSource.VECTISPIRE)),
                                measured(VULN, ComplianceControl.Status.COMPLIANT)),
                        VULN))
                .isEqualTo(Divergence.UNDERSTATED);
    }

    @Test
    @DisplayName("counts a lapsed review whatever the line otherwise says")
    void lapsedReviewIsCountedSeparately() {
        Declaration stale = new Declaration(
                FRAMEWORK_KEY, VULN, Applicability.APPLICABLE, "In scope.", Implementation.IMPLEMENTED,
                EvidenceSource.VECTISPIRE, null, "n.faure", "c.moreau",
                NOW.minusSeconds(400L * 86_400), NOW.minusSeconds(400L * 86_400), NOW.minusSeconds(86_400));

        SoaStatement statement = reconcile(List.of(stale), measured(VULN, ComplianceControl.Status.COMPLIANT));

        assertThat(divergenceOf(statement, VULN))
                .as("the claim still matches the estate — what lapsed is the confirmation of it")
                .isEqualTo(Divergence.CONSISTENT);
        assertThat(statement.reviewsOverdue()).isEqualTo(1);
    }

    @Test
    @DisplayName("ignores a declaration naming a control this framework does not have")
    void foreignControlsAreDropped() {
        Declaration ghost = declared("ISO-A.99.99", Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE);

        SoaStatement statement = reconcile(List.of(ghost), measured(VULN, ComplianceControl.Status.COMPLIANT));

        assertThat(statement.lines())
                .as("a row for a control the framework denies would be a document contradicting itself")
                .extracting(line -> line.control().id())
                .doesNotContain("ISO-A.99.99");
    }

    @Test
    @DisplayName("ignores a declaration belonging to another framework")
    void otherFrameworksAreDropped() {
        Declaration elsewhere = new Declaration(
                ComplianceFramework.SOC_2.name(), VULN, Applicability.APPLICABLE, "In scope.",
                Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, null,
                "n.faure", "c.moreau", NOW, NOW, null);

        assertThat(divergenceOf(
                        reconcile(List.of(elsewhere), measured(VULN, ComplianceControl.Status.NON_COMPLIANT)), VULN))
                .isEqualTo(Divergence.UNDECLARED);
    }

    private static Divergence divergenceOf(SoaStatement statement, String controlId) {
        return statement.lines().stream()
                .filter(line -> line.control().id().equals(controlId))
                .map(Line::divergence)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no line for " + controlId));
    }

    private static Declaration declared(String controlId, Implementation implementation, EvidenceSource source) {
        return new Declaration(
                FRAMEWORK_KEY, controlId, Applicability.APPLICABLE, "In scope.", implementation, source,
                source == EvidenceSource.VECTISPIRE ? null : "Named elsewhere",
                "n.faure", "c.moreau", NOW, NOW, NOW.plusSeconds(86_400));
    }

    private static SoaStatement reconcile(List<Declaration> declarations, ComplianceEvaluation evaluation) {
        return StatementOfApplicability.reconcile(evaluation, declarations, NOW);
    }

    /** An evaluation saying one thing about one control and nothing about the rest. */
    private static ComplianceEvaluation measured(String controlId, ComplianceControl.Status status) {
        ComplianceControl control = FRAMEWORK.getControls().stream()
                .filter(candidate -> candidate.id().equals(controlId))
                .findFirst()
                .orElseThrow();
        return new ComplianceEvaluation(
                FRAMEWORK, 0, ComplianceControl.Status.PARTIAL,
                List.of(new ComplianceEvaluation.ControlAssessment(control, status, 0, "", "")));
    }
}
