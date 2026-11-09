package com.asmolabs.vectispire.common.domain.threatintel;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the EPSS and KEV risk matrix prioritization formulas")
class EpssRiskMatrixTest {

    @Test
    @DisplayName("calculates high priority score for a CISA KEV vulnerability")
    void calculatesCriticalKevScore() {
        // 9.8 / 10 × 30 + min(40, 0.75 × 80) + 30 = 29.4 + 40 + 30, capped at 100.
        assertThat(EpssRiskMatrix.calculatePriorityScore(9.8, 0.75, true)).isEqualTo(99);

        String tier = EpssRiskMatrix.determineTier(9.8, 0.75, true);
        assertThat(tier).isEqualTo("CRITICAL_ARMED");

        assertThat(EpssRiskMatrix.determineAction(tier, true))
                .as("listed in the KEV catalogue, so the shortest deadline of the two P0s")
                .isEqualTo(EpssRiskMatrix.RecommendedAction.P0_KEV_24H);
    }

    @Test
    @DisplayName("calculates moderate score for theoretical CVE with low EPSS")
    void calculatesTheoreticalScore() {
        // 8.0 / 10 × 30 + 0.001 × 80 = 24.08.
        assertThat(EpssRiskMatrix.calculatePriorityScore(8.0, 0.001, false)).isEqualTo(24);

        String tier = EpssRiskMatrix.determineTier(8.0, 0.001, false);
        assertThat(tier).isEqualTo("MEDIUM_THEORETICAL");

        assertThat(EpssRiskMatrix.determineAction(tier, false))
                .isEqualTo(EpssRiskMatrix.RecommendedAction.P2_30D);
    }

    /**
     * The quadrants the screen explains, and only those.
     *
     * <p>An EPSS of 20 % on a high CVSS reached the top tier when the issue read reachable — a
     * clause the screen's legend never mentioned, weighing a column nothing computes. It is the
     * second quadrant: probable, not armed.
     */
    @Test
    @DisplayName("a probable exploit that is neither listed nor above 50 % stays in the second quadrant")
    void probableIsNotArmed() {
        assertThat(EpssRiskMatrix.determineTier(8.0, 0.30, false)).isEqualTo("HIGH_PROBABLE");
        assertThat(EpssRiskMatrix.determineTier(8.0, 0.50, false)).isEqualTo("CRITICAL_ARMED");
        // 24 + 24: no multiplier on top of CVSS, EPSS and KEV.
        assertThat(EpssRiskMatrix.calculatePriorityScore(8.0, 0.30, false)).isEqualTo(48);
    }
}
