package com.asmolabs.vectispire.common.domain.threatintel;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the EPSS and KEV risk matrix prioritization formulas")
class EpssRiskMatrixTest {

    @Test
    @DisplayName("calculates high priority score for CISA KEV and reachable vulnerability")
    void calculatesCriticalKevScore() {
        int score = EpssRiskMatrix.calculatePriorityScore(9.8, 0.75, true, "REACHABLE");
        assertThat(score).isGreaterThanOrEqualTo(90);
        assertThat(score).isLessThanOrEqualTo(100);

        String tier = EpssRiskMatrix.determineTier(9.8, 0.75, true, "REACHABLE");
        assertThat(tier).isEqualTo("CRITICAL_ARMED");

        String action = EpssRiskMatrix.determineAction(tier, true, "REACHABLE");
        assertThat(action).contains("P0");
    }

    @Test
    @DisplayName("calculates moderate score for theoretical CVE with low EPSS")
    void calculatesTheoreticalScore() {
        int score = EpssRiskMatrix.calculatePriorityScore(8.0, 0.001, false, "UNREACHABLE");
        assertThat(score).isLessThan(40);

        String tier = EpssRiskMatrix.determineTier(8.0, 0.001, false, "UNREACHABLE");
        assertThat(tier).isEqualTo("MEDIUM_THEORETICAL");

        String action = EpssRiskMatrix.determineAction(tier, false, "UNREACHABLE");
        assertThat(action).contains("P2");
    }
}
