package com.asmolabs.vectispire.common.domain.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The one reading of "was this target examined", shared by the security screen and the gate.
 *
 * <p>Every status is asked, so that a status added to {@link ScanStatus} without a decision here
 * shows up as a classification somebody has to read rather than one that defaulted.
 */
@DisplayName("observation of a target's scans")
class ObservationTest {

    @Test
    @DisplayName("no scan at all is never scanned, and not an examination")
    void noScanIsNeverScanned() {
        assertThat(Observation.of(Optional.empty())).isEqualTo(Observation.NEVER_SCANNED);
        assertThat(Observation.NEVER_SCANNED.examined()).isFalse();
    }

    @Test
    @DisplayName("a failed scan is the last scan failed, and not an examination")
    void failedIsLastScanFailed() {
        assertThat(Observation.of(Optional.of(ScanStatus.FAILED))).isEqualTo(Observation.LAST_SCAN_FAILED);
        assertThat(Observation.LAST_SCAN_FAILED.examined()).isFalse();
    }

    @Test
    @DisplayName("a pending or running scan is in progress, and not an examination yet")
    void inFlightIsInProgress() {
        assertThat(Observation.of(Optional.of(ScanStatus.PENDING))).isEqualTo(Observation.IN_PROGRESS);
        assertThat(Observation.of(Optional.of(ScanStatus.SCANNING))).isEqualTo(Observation.IN_PROGRESS);
        assertThat(Observation.IN_PROGRESS.examined()).isFalse();
    }

    @Test
    @DisplayName("a completed scan is the one examination there is")
    void completedIsExamined() {
        assertThat(Observation.of(Optional.of(ScanStatus.COMPLETED))).isEqualTo(Observation.OK);
        assertThat(Observation.OK.examined()).isTrue();
    }

    @Test
    @DisplayName("every observation but OK carries the sentence a refused verdict shows")
    void everyRefusalSaysWhy() {
        for (Observation observation : Observation.values()) {
            assertThat(observation.refusal().isPresent()).as(observation.name()).isEqualTo(!observation.examined());
        }
    }
}
