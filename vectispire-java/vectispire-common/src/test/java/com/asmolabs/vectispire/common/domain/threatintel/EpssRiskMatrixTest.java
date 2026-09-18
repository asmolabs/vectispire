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

        assertThat(EpssRiskMatrix.determineAction(tier, true, "REACHABLE"))
                .as("listed in the KEV catalogue, so the shortest deadline of the two P0s")
                .isEqualTo(EpssRiskMatrix.RecommendedAction.P0_KEV_24H);
    }

    @Test
    @DisplayName("calculates moderate score for theoretical CVE with low EPSS")
    void calculatesTheoreticalScore() {
        int score = EpssRiskMatrix.calculatePriorityScore(8.0, 0.001, false, "UNREACHABLE");
        assertThat(score).isLessThan(40);

        String tier = EpssRiskMatrix.determineTier(8.0, 0.001, false, "UNREACHABLE");
        assertThat(tier).isEqualTo("MEDIUM_THEORETICAL");

        assertThat(EpssRiskMatrix.determineAction(tier, false, "UNREACHABLE"))
                .isEqualTo(EpssRiskMatrix.RecommendedAction.P2_30D);
    }
}
