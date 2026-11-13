package com.asmolabs.vectispire.core.golden;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the traffic recorder")
class TrafficRecorderTest {

    @Test
    @DisplayName("keeps a PEM answer as text, where its key can be hidden, and a document as a binary sidecar")
    void aPemIsText() {
        assertThat(TrafficRecorder.isTextual("application/x-pem-file;charset=utf-8")).isTrue();
        assertThat(TrafficRecorder.isTextual("application/x-pem-file")).isTrue();
        assertThat(TrafficRecorder.isTextual("application/json")).isTrue();
        assertThat(TrafficRecorder.isTextual("application/pdf")).isFalse();
        assertThat(TrafficRecorder.isTextual("application/zip")).isFalse();
        assertThat(TrafficRecorder.isTextual("application/octet-stream")).isFalse();
    }

    @Test
    @DisplayName("marks a time the test moved back across the present as past, and no other change")
    void aRewoundTimeIsMarkedPast() throws Exception {
        LocalDateTime present = LocalDateTime.parse("2026-11-13T10:00:00");
        JsonNode seed = new ObjectMapper().readTree("""
                {"t_scan": {"updated": [{"key": {"id": 1}, "changed": {
                  "lease_expires_at": {"from": "2026-11-13T10:05:00", "to": "2026-11-13T09:59:00"},
                  "not_before": {"from": "2026-11-13T10:01:00", "to": "2026-11-13T10:00:30"},
                  "last_seen_at": {"from": "2026-11-13T09:58:00", "to": "2026-11-13T09:59:30"},
                  "claimed_at": {"from": "2026-11-13T09:50:00", "to": "2026-11-13T09:40:00"},
                  "status": {"from": "scanning", "to": "pending"}}}]}}""");

        JsonNode changed = TrafficRecorder.markRewoundTimes(seed, present).at("/t_scan/updated/0/changed");

        assertThat(changed.at("/lease_expires_at/to").asText()).isEqualTo(TrafficRecorder.PAST);
        // Moved back but still ahead: not past, and left to the placeholders.
        assertThat(changed.at("/not_before/to").asText()).isEqualTo("2026-11-13T10:00:30");
        // Moved forward: a session's last sight, dropped as before.
        assertThat(changed.at("/last_seen_at/to").asText()).isEqualTo("2026-11-13T09:59:30");
        // Already past before the change: it crossed nothing.
        assertThat(changed.at("/claimed_at/to").asText()).isEqualTo("2026-11-13T09:40:00");
        assertThat(changed.at("/status/to").asText()).isEqualTo("pending");
    }
}
