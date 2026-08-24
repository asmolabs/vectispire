package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.repositories.TeamWebhooks;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("deciding what a webhook is told")
class NotificationServiceTest {

    private SettingsService settings;
    private OutboundPost post;
    private TeamWebhooks teamWebhooks;
    private NotificationService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        post = mock(OutboundPost.class);
        // No team channel in this suite: it is about what to say and to whom by default. The
        // routing has its own.
        teamWebhooks = mock(TeamWebhooks.class);
        service = new NotificationService(
                settings,
                post,
                teamWebhooks,
                mock(EncryptionService.class),
                Clock.fixed(Instant.parse("2026-08-22T10:00:00Z"), ZoneOffset.UTC));

        when(settings.get(Setting.WEBHOOK_URL)).thenReturn("https://hooks.example.com/z");
        when(settings.get(Setting.NOTIFICATION_MIN_SEVERITY)).thenReturn("high");
        // Unsigned: signing has its own suite, and a secret here would make every assertion
        // about the payload depend on a decryption it does not care about.
        when(settings.get(Setting.WEBHOOK_SIGNING_SECRET)).thenReturn("");
        when(settings.isEnabled(Setting.NOTIFY_ON_KEV)).thenReturn(true);
        when(settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)).thenReturn(false);
    }

    @Test
    @DisplayName("no URL means no notifications at all")
    void anUnsetUrlDisablesEverything() {
        when(settings.get(Setting.WEBHOOK_URL)).thenReturn("   ");

        assertThat(service.isEnabled()).isFalse();
        assertThat(service.buildScanDelta("service", 1, List.of(issue(Severity.CRITICAL, false)), List.of(), 0))
                .isEmpty();
    }

    @Test
    @DisplayName("nothing above the threshold means nothing to say")
    void anEmptyDeltaProducesNoMessage() {
        assertThat(service.buildScanDelta("service", 1, List.of(issue(Severity.LOW, false)), List.of(), 3)).isEmpty();
    }

    @Test
    @DisplayName("an exploited vulnerability passes below the threshold")
    void kevOverridesTheThreshold() {
        assertThat(service.buildScanDelta("service", 1, List.of(issue(Severity.LOW, true)), List.of(), 0))
                .get()
                .returns(1, NotificationPayload::newCount)
                .returns(1L, NotificationPayload::kevCount);
    }

    @Test
    @DisplayName("a misspelled threshold falls back to the default rather than letting everything through")
    void anUnreadableSeverityDoesNotDisableTheThreshold() {
        when(settings.get(Setting.NOTIFICATION_MIN_SEVERITY)).thenReturn("prettybad");

        assertThat(service.minSeverity()).isEqualTo(Severity.HIGH);
        assertThat(service.buildScanDelta("service", 1, List.of(issue(Severity.MEDIUM, false)), List.of(), 0))
                .isEmpty();
    }

    @Test
    @DisplayName("the URL is re-read at delivery, not captured when queued")
    void theDestinationIsValidatedAtSendTime() {
        when(settings.get(Setting.WEBHOOK_URL)).thenReturn("https://corrected.example.com/z");

        service.deliver(payload(), null);

        // An operator fixing a typo must not have to re-run a scan to flush what is pending.
        verify(post)
                .postSignedJson(
                        eq("https://corrected.example.com/z"),
                        any(),
                        eq(OutboundPolicy.PUBLIC_ONLY),
                        anyString(),
                        anyString(),
                        any());
    }

    @Test
    @DisplayName("an internal webhook is only allowed when the operator said so")
    void thePolicyFollowsTheSetting() {
        when(settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)).thenReturn(true);

        service.deliver(payload(), null);

        verify(post)
                .postSignedJson(
                        anyString(), any(), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString(), anyString(), any());
    }

    private static NotificationPayload payload() {
        return NotificationPayload.of(new NotificationPayload.Delta(
                "service", 4, List.of(issue(Severity.HIGH, false)), List.of(), 0, Severity.HIGH));
    }

    private static NotifiableIssue issue(Severity severity, boolean kev) {
        return new NotifiableIssue(
                1L, "CVE-2026-1", FindingType.VULNERABILITY, severity, kev, 0.1, "openssl", null, "3.5.2", null);
    }
}
