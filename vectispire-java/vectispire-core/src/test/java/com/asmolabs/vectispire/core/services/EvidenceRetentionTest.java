package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.retention.RetentionPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.repositories.GateVerdicts;
import com.asmolabs.vectispire.core.repositories.LoginAttempts;
import com.asmolabs.vectispire.core.repositories.MfaChallenges;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * How long the gate verdict register survives.
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

    private GateVerdicts verdicts;
    private SettingsService settings;
    private SessionCleanupService cleanup;

    @BeforeEach
    void wire() {
        verdicts = mock(GateVerdicts.class);
        settings = mock(SettingsService.class);
        UserSessions sessions = mock(UserSessions.class);
        LoginAttempts attempts = mock(LoginAttempts.class);
        MfaChallenges challenges = mock(MfaChallenges.class);
        cleanup = new SessionCleanupService(
                sessions, attempts, challenges, verdicts, settings, Clock.fixed(NOW, ZoneOffset.UTC));
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
        when(verdicts.deleteBefore(any())).thenReturn(7);

        assertThat(cleanup.prune().verdicts()).isEqualTo(7);
        verify(verdicts).deleteBefore(NOW.minus(java.time.Duration.ofDays(400)));
    }

    @Test
    @DisplayName("keeps everything when set to zero")
    void zeroKeepsEverything() {
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(0);

        assertThat(cleanup.prune().verdicts()).isZero();
        verify(verdicts, never()).deleteBefore(any());
    }

    @Test
    @DisplayName("ignores the raw-payload window entirely")
    void doesNotFollowThePayloadWindow() {
        when(settings.asInt(Setting.RETENTION_MAX_AGE_DAYS)).thenReturn(1);
        when(settings.asInt(Setting.EVIDENCE_RETENTION_DAYS)).thenReturn(400);

        cleanup.prune();

        verify(verdicts).deleteBefore(NOW.minus(java.time.Duration.ofDays(400)));
    }
}
