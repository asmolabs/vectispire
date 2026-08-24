package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("purging raw scanner payloads")
class RetentionServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T03:00:00Z");

    private Scans scans;
    private SettingsService settings;
    private RetentionService retention;

    @BeforeEach
    void wire() {
        scans = mock(Scans.class);
        settings = mock(SettingsService.class);
        retention = new RetentionService(scans, settings, Clock.fixed(NOW, ZoneOffset.UTC));

        when(settings.asInt(Setting.RETENTION_KEEP_PER_TARGET)).thenReturn(2);
        when(settings.asInt(Setting.RETENTION_MAX_AGE_DAYS)).thenReturn(90);
        when(scans.findPayloadBearing()).thenReturn(List.of());
    }

    @Test
    @DisplayName("the most recent scans of a target are kept whatever their age")
    void keepsTheWindowPerTarget() {
        when(scans.findPayloadBearing()).thenReturn(List.<Object[]>of(
                row(1, 7L, null, NOW.minus(java.time.Duration.ofDays(400))),
                row(2, 7L, null, NOW.minus(java.time.Duration.ofDays(401))),
                row(3, 7L, null, NOW.minus(java.time.Duration.ofDays(402)))));

        assertThat(retention.findPrunable()).containsExactly(3L);
    }

    @Test
    @DisplayName("both axes must agree before a payload goes")
    void ageAndWindowCombine() {
        // Outside the keep window but younger than the age limit: kept.
        when(scans.findPayloadBearing()).thenReturn(List.<Object[]>of(
                row(1, 7L, null, NOW.minusSeconds(60)),
                row(2, 7L, null, NOW.minusSeconds(120)),
                row(3, 7L, null, NOW.minusSeconds(180))));

        assertThat(retention.findPrunable()).isEmpty();
    }

    @Test
    @DisplayName("both settings at zero disables purging entirely")
    void zeroAndZeroMeansNothingIsPurged() {
        when(settings.asInt(Setting.RETENTION_KEEP_PER_TARGET)).thenReturn(0);
        when(settings.asInt(Setting.RETENTION_MAX_AGE_DAYS)).thenReturn(0);
        when(scans.findPayloadBearing()).thenReturn(List.<Object[]>of(row(1, 7L, null, NOW.minusSeconds(1))));

        assertThat(retention.findPrunable()).isEmpty();
        verify(scans, never()).findPayloadBearing();
    }

    @Test
    @DisplayName("targets are counted separately")
    void eachTargetHasItsOwnWindow() {
        when(scans.findPayloadBearing()).thenReturn(List.<Object[]>of(
                row(1, 7L, null, NOW.minus(java.time.Duration.ofDays(400))),
                row(2, null, 4L, NOW.minus(java.time.Duration.ofDays(401))),
                row(3, 7L, null, NOW.minus(java.time.Duration.ofDays(402))),
                row(4, null, 4L, NOW.minus(java.time.Duration.ofDays(403)))));

        // Two per target kept, and there are exactly two of each.
        assertThat(retention.findPrunable()).isEmpty();
    }

    @Test
    @DisplayName("a long list is erased in batches, not in one clause")
    void largePurgesAreBatched() {
        List<Object[]> rows = new ArrayList<>();
        for (int i = 1; i <= 1200; i++) {
            // One target, so all but the two most recent fall outside the keep window.
            rows.add(row(i, 7L, null, NOW.minus(java.time.Duration.ofDays(400 + i))));
        }
        when(scans.findPayloadBearing()).thenReturn(rows);

        assertThat(retention.prune()).isEqualTo(1198);
        // 500 at a time: an `in` clause of tens of thousands exceeds some drivers' limits, and a
        // long-neglected database is exactly where the list is long.
        verify(scans, times(3)).dropPayloads(any());
    }

    @Test
    void reportsHowManyStillCarryAPayload() {
        when(scans.countPayloadBearing()).thenReturn(42L);

        assertThat(retention.payloadCount()).isEqualTo(42);
    }

    private static Object[] row(long id, Long repoId, Long containerId, Instant createdAt) {
        return new Object[] {id, repoId, containerId, createdAt};
    }
}
