package com.asmolabs.vectispire.common.domain.vex;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.vex.VexDisposition.Kind;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Decision 0041 §3: one reading of the triage, which every VEX format spells. */
@DisplayName("what a triage states in VEX")
class VexDispositionTest {

    @Test
    @DisplayName("the table of decision 0041, row by row")
    void theTable() {
        assertThat(VexDisposition.of(TriageStatus.UNDER_REVIEW, null, false).kind()).isEqualTo(Kind.UNDER_INVESTIGATION);
        assertThat(VexDisposition.of(TriageStatus.PENDING_APPROVAL, "component_not_present", false).kind())
                .as("a request is nobody's conclusion yet").isEqualTo(Kind.UNDER_INVESTIGATION);
        assertThat(VexDisposition.of(TriageStatus.AFFECTED, null, false).kind()).isEqualTo(Kind.AFFECTED);
        assertThat(VexDisposition.of(TriageStatus.WILL_NOT_FIX, null, false).kind()).isEqualTo(Kind.WILL_NOT_FIX);
        assertThat(VexDisposition.of(TriageStatus.NOT_AFFECTED, "vulnerable_code_not_present", false))
                .isEqualTo(new VexDisposition(Kind.NOT_AFFECTED,
                        java.util.Optional.of(VexJustification.VULNERABLE_CODE_NOT_PRESENT)));
        assertThat(VexDisposition.of(TriageStatus.FIXED, null, false).kind()).isEqualTo(Kind.FIXED);
        assertThat(VexDisposition.of((TriageStatus) null, null, false).kind()).isEqualTo(Kind.UNDER_INVESTIGATION);
    }

    @Test
    @DisplayName("a not_affected nobody justified is under investigation, never given a justification")
    void noJustificationIsInvented() {
        assertThat(VexDisposition.of(TriageStatus.NOT_AFFECTED, null, false).kind()).isEqualTo(Kind.UNDER_INVESTIGATION);
        assertThat(VexDisposition.of(TriageStatus.NOT_AFFECTED, "  ", false).kind()).isEqualTo(Kind.UNDER_INVESTIGATION);
        assertThat(VexDisposition.of(TriageStatus.NOT_AFFECTED, "unreachable-ish", false).kind())
                .as("an unknown word is no justification").isEqualTo(Kind.UNDER_INVESTIGATION);
    }

    @ParameterizedTest
    @EnumSource(TriageStatus.class)
    @DisplayName("an issue no longer found is fixed, whatever its triage")
    void resolvedIsFixed(TriageStatus status) {
        assertThat(VexDisposition.of(status, "component_not_present", true).kind()).isEqualTo(Kind.FIXED);
    }

    @Test
    @DisplayName("an accepted risk is never stated as not affected — the claim this decision withdraws")
    void anAcceptedRiskIsExposure() {
        VexDisposition accepted = VexDisposition.of("will_not_fix", "inline_mitigations_already_exist", false);
        assertThat(accepted.kind()).isEqualTo(Kind.WILL_NOT_FIX);
        assertThat(accepted.justification()).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(VexJustification.class)
    @DisplayName("every justification has a CycloneDX spelling from CycloneDX's own vocabulary")
    void cycloneDxVocabulary(VexJustification justification) {
        assertThat(VexDisposition.cycloneDxJustification(justification)).isIn("code_not_present", "code_not_reachable",
                "requires_configuration", "requires_dependency", "requires_environment", "protected_by_compiler",
                "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control");
    }
}
