package com.asmolabs.zanshin.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Telling "looked and found nothing" from "never looked", at the level of the whole scan.
 *
 * <p>The distinction is already enforced per step by the {@code Optional} fields. What was
 * missing was the same question asked of the scan itself, which is what an operator actually
 * reads: a scan whose every step is absent examined nothing, and reporting it as completed says
 * the opposite of what happened.
 */
@DisplayName("what a scan actually observed")
class ScanArtifactsTest {

    @Test
    @DisplayName("every step absent means nothing was examined")
    void allAbsentIsNothingObserved() {
        ScanArtifacts artifacts = ScanArtifacts.builder()
                .failed("dependencies", "pull access denied for temurin")
                .build(Duration.ofSeconds(3));

        assertThat(artifacts.observedNothing()).isTrue();
    }

    @Test
    @DisplayName("one step that ran and found nothing is still an observation")
    void anEmptyResultIsAnObservation() {
        // The whole point of decision 0007, at scan level: an empty list is a finding about the
        // target. Treating it as "nothing examined" would mark every clean scan as failed.
        ScanArtifacts artifacts =
                ScanArtifacts.builder().secrets(java.util.List.of()).build(Duration.ofSeconds(3));

        assertThat(artifacts.observedNothing()).isFalse();
    }

    @Test
    @DisplayName("an SBOM alone is not an observation")
    void anSbomDoesNotCount() {
        // A description of the target, not a finding about it. A scan that inventoried the
        // packages and then failed every analysis has still analysed nothing.
        ScanArtifacts artifacts = ScanArtifacts.builder()
                .sbom(new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode())
                .failed("dependencies", "grype timed out")
                .build(Duration.ofSeconds(3));

        assertThat(artifacts.observedNothing()).isTrue();
    }
}
