package com.asmolabs.zanshin.common.domain.licenses;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the License Conflict Matrix domain engine")
class LicenseConflictMatrixTest {

    @Test
    @DisplayName("identifies strong copyleft GPL contamination on proprietary target as blocking")
    void detectsGplContamination() {
        LicenseConflictMatrix.LicenseConflict conflict = LicenseConflictMatrix.evaluate(
                "gpl-library",
                "1.0.0",
                "GPL-3.0",
                "REPOSITORY",
                "corp-backend",
                true);

        assertThat(conflict.compatibility()).isEqualTo(LicenseConflictMatrix.Compatibility.INCOMPATIBLE_BLOCKING);
        assertThat(conflict.riskCategory()).isEqualTo(LicenseRiskCategory.STRONG_COPYLEFT);
        assertThat(conflict.legalRiskExplanation()).contains("Contamination Copyleft Forte");
        assertThat(conflict.remediationAdvice()).contains("Remplacer");
    }

    @Test
    @DisplayName("identifies permissive license as compatible")
    void detectsPermissiveCompatibility() {
        LicenseConflictMatrix.LicenseConflict conflict = LicenseConflictMatrix.evaluate(
                "lodash",
                "4.17.21",
                "MIT",
                "REPOSITORY",
                "corp-frontend",
                true);

        assertThat(conflict.compatibility()).isEqualTo(LicenseConflictMatrix.Compatibility.COMPATIBLE);
        assertThat(conflict.riskCategory()).isEqualTo(LicenseRiskCategory.PERMISSIVE);
    }

    @Test
    @DisplayName("identifies weak copyleft as conditional with dynamic linking guidance")
    void detectsWeakCopyleft() {
        LicenseConflictMatrix.LicenseConflict conflict = LicenseConflictMatrix.evaluate(
                "logback-core",
                "1.4.0",
                "LGPL-2.1",
                "REPOSITORY",
                "corp-backend",
                true);

        assertThat(conflict.compatibility()).isEqualTo(LicenseConflictMatrix.Compatibility.CONDITIONAL);
        assertThat(conflict.riskCategory()).isEqualTo(LicenseRiskCategory.WEAK_COPYLEFT);
        assertThat(conflict.legalRiskExplanation()).contains("dynamiquement");
    }
}
