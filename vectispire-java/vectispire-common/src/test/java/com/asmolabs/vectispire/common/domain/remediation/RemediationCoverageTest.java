package com.asmolabs.vectispire.common.domain.remediation;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("what the remediation plan leaves to do")
class RemediationCoverageTest {

    @Test
    @DisplayName("findings counted only on request — AI review, plugins, imports — are not in the total unasked")
    void onRequestFamiliesAreLeftOut() {
        RemediationCoverage coverage = RemediationCoverage.of(List.of(
                new RemediationCoverage.OpenFamily("vulnerability", 4, 0),
                new RemediationCoverage.OpenFamily("sast", 0, 3),
                new RemediationCoverage.OpenFamily("ai_review", 0, 7),
                new RemediationCoverage.OpenFamily("plugin", 0, 11),
                new RemediationCoverage.OpenFamily("imported", 0, 13)));

        assertThat(coverage.openFindings()).isEqualTo(7);
        assertThat(coverage.beyondUpgrades()).isEqualTo(3);
        assertThat(coverage.gaps()).extracting(RemediationGap::family).containsExactly("sast");
    }

    @Test
    @DisplayName("a type this version does not know is still counted, under its own name")
    void unknownTypesStay() {
        RemediationCoverage coverage = RemediationCoverage.of(List.of(new RemediationCoverage.OpenFamily("future", 1, 1)));

        assertThat(coverage.gaps()).extracting(RemediationGap::family).containsExactly("future");
    }
}
