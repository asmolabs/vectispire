package com.asmolabs.zanshin.common.domain.threatintel;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ThreatIntelSyncStatus representation")
class ThreatIntelSyncStatusTest {

    @Test
    @DisplayName("records feed status and metrics correctly")
    void recordsSyncStatus() {
        Instant now = Instant.parse("2026-08-22T12:00:00Z");
        ThreatIntelSyncStatus status = new ThreatIntelSyncStatus(now, 125000, 1150, "SYNCED", 42);

        assertThat(status.lastSyncedAt()).isEqualTo(now);
        assertThat(status.totalCves()).isEqualTo(125000);
        assertThat(status.totalKev()).isEqualTo(1150);
        assertThat(status.status()).isEqualTo("SYNCED");
        assertThat(status.backlogUpdatedCount()).isEqualTo(42);
    }
}
