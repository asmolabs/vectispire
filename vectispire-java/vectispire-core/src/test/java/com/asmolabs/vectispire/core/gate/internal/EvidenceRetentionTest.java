package com.asmolabs.vectispire.core.gate.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.retention.RetentionPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.compliance.internal.SnapshotRetentionTask;
import com.asmolabs.vectispire.core.compliance.persistence.ComplianceSnapshotRepository;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * How long the gate verdict register survives, and the compliance captures with it.
 *
 * <p><b>The defect this guards is silent and slow.</b> The register followed the raw-payload
 * window, ninety days by default, so an instance running perfectly well would present an assessor
 * with an empty answer to "show me that the barrier refused something during the audited period".
 * Nothing logs, nothing fails, and the operator finds out in the meeting.
 *
 * <p>Which is why the first case below asserts a number rather than a behaviour: the whole point
 * is that this window is <em>not</em> the payload window, and a future tidy-up that unified them
 * again would look like a simplification.
 */
@DisplayName("evidence retention")
class EvidenceRetentionTest {

    private static final Instant NOW = Instant.parse("2026-09-14T10:00:00Z");

    private GateVerdictRepository verdicts;
    private ComplianceSnapshotRepository snapshots;
    private SettingsService settings;
    private VerdictRetentionTask verdictRetention;
    private SnapshotRetentionTask snapshotRetention;

    @BeforeEach
    void wire() {
        verdicts = mock(GateVerdictRepository.class);
        snapshots = mock(ComplianceSnapshotRepository.class);
        settings = mock(SettingsService.class);
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        verdictRetention = new VerdictRetentionTask(verdicts, settings, clock);
        snapshotRetention = new SnapshotRetentionTask(snapshots, settings, clock);
    }

    @Test
    @DisplayName("outlives an annual audit, unlike the payload window")
    void defaultCoversAnAuditCycle() {
        assertThat(EvidenceRetention.DEFAULT.toDays())
                .as("twelve months plus the delay before an assessor reads the period")
                .isGreaterThanOrEqualTo(365);
        assertThat(EvidenceRetention.DEFAULT)
                .as("kept apart from the raw-payload window on purpose")
                .isNotEqualTo(RetentionPolicy.DEFAULT.maxAge());
    }

    @Test
    @DisplayName("purges verdicts older than the configured window")
    void purgesBeyondTheWindow() {
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(400);

        verdictRetention.run();

        verify(verdicts).deleteBefore(NOW.minus(Duration.ofDays(400)));
    }

    @Test
    @DisplayName("keeps everything when set to zero")
    void zeroKeepsEverything() {
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(0);

        verdictRetention.run();
        snapshotRetention.run();

        verify(verdicts, never()).deleteBefore(any());
        verify(snapshots, never()).deleteBefore(any());
    }

    @Test
    @DisplayName("ignores the raw-payload window entirely")
    void doesNotFollowThePayloadWindow() {
        when(settings.asInt(Setting.RETENTION_MAX_AGE_DAYS)).thenReturn(1);
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(400);

        verdictRetention.run();

        verify(verdicts).deleteBefore(NOW.minus(Duration.ofDays(400)));
    }

    @Test
    @DisplayName("purges the compliance captures by the same dial")
    void theCapturesFollowTheSameDial() {
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(400);

        snapshotRetention.run();

        // One dial for all evidence: a second window for the captures would be the drift the single
        // setting exists to prevent.
        verify(snapshots).deleteBefore(NOW.minus(Duration.ofDays(400)));
    }

    @Test
    @DisplayName("a failing purge skips its table and does not end the turn")
    void aFailureIsSwallowed() {
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(400);
        when(verdicts.deleteBefore(any())).thenThrow(new IllegalStateException("locked"));

        // Inside the authentication pass, a failing evidence purge skipped its own table and nothing
        // else; as a task of its own it must not end the hourly turn either, which a throwing task
        // does.
        verdictRetention.run();
    }
}
