package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("which triage decisions reach the SOC")
class TriageSignalsTest {

    @Test
    @DisplayName("settling directly — not affected, or fixed — is a settled finding")
    void settlingDirectly() {
        assertThat(TriageSignals.of(List.of("under_review"), "not_affected")).contains(SecurityEventType.TRIAGE_SETTLED);
        assertThat(TriageSignals.of(Arrays.asList((String) null), "fixed")).contains(SecurityEventType.TRIAGE_SETTLED);
    }

    @Test
    @DisplayName("settling a pending request is an approval")
    void approving() {
        assertThat(TriageSignals.of(List.of("pending_approval"), "not_affected")).contains(SecurityEventType.TRIAGE_APPROVED);
        // In a bulk decision one request among the selection is enough to make it an answer.
        assertThat(TriageSignals.of(List.of("affected", "pending_approval"), "fixed"))
                .contains(SecurityEventType.TRIAGE_APPROVED);
    }

    @Test
    @DisplayName("sending a pending request back is a refusal")
    void refusing() {
        assertThat(TriageSignals.of(List.of("pending_approval"), "under_review")).contains(SecurityEventType.TRIAGE_REFUSED);
        assertThat(TriageSignals.of(List.of("pending_approval"), "affected")).contains(SecurityEventType.TRIAGE_REFUSED);
    }

    @Test
    @DisplayName("housekeeping and requests are not forwarded")
    void quietDecisions() {
        assertThat(TriageSignals.of(List.of("affected"), "under_review")).isEmpty();
        // A dismissal by somebody who cannot approve lands as a request: the control working.
        assertThat(TriageSignals.of(List.of("under_review"), "pending_approval")).isEmpty();
        assertThat(TriageSignals.of(List.of("pending_approval"), "pending_approval")).isEmpty();
        assertThat(TriageSignals.of(List.of("under_review"), "a_status_from_the_future")).isEmpty();
    }
}
