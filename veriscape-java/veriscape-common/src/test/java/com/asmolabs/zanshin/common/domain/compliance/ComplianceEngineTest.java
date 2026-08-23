package com.asmolabs.zanshin.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ComplianceEngine regulatory assessment")
class ComplianceEngineTest {

    @Test
    @DisplayName("evaluates 100% compliant when security posture is clean")
    void perfectCompliance() {
        ComplianceEngine.PostureInput cleanPosture = new ComplianceEngine.PostureInput(
                10, 10, 10,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                10,
                true);

        List<ComplianceEvaluation> results = ComplianceEngine.evaluateAll(cleanPosture);

        assertThat(results).hasSize(5);
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

        List<ComplianceEvaluation> results = ComplianceEngine.evaluateAll(flawedPosture);

        assertThat(results).hasSize(5);
        for (ComplianceEvaluation eval : results) {
            assertThat(eval.scorePercentage()).isLessThan(70);
            assertThat(eval.overallStatus()).isEqualTo(ComplianceControl.Status.NON_COMPLIANT);
        }
    }
}
