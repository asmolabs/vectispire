package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.data.jpa.domain.Specification;

/**
 * What a successful send records, and what a failed one must not.
 *
 * <p>{@code PostureDigestDatabaseTest} proves the gating against a real log. This one closes the
 * link that gating rests on: <b>a send that worked writes the entry, and a send that threw does
 * not</b>. Get the first wrong and a deployment receives one report an hour until Monday; get the
 * second wrong and one broken relay on a Monday morning buys a week of silence.
 */
@DisplayName("recording that the weekly report went out")
class PostureDigestServiceTest {

    private static final Instant WEDNESDAY = Instant.parse("2026-08-19T09:00:00Z");

    private SettingsService settings;
    private AuditLog auditLog;
    private AuditLogService audit;
    private NotificationService webhook;
    private MailNotificationChannel mail;
    private OutboundPost post;
    private PostureDigestService digest;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        auditLog = mock(AuditLog.class);
        audit = mock(AuditLogService.class);
        webhook = mock(NotificationService.class);
        mail = mock(MailNotificationChannel.class);
        post = mock(OutboundPost.class);

        GateService gate = mock(GateService.class);
        SlaService sla = mock(SlaService.class);
        Issues issues = mock(Issues.class);

        when(settings.isEnabled(Setting.DIGEST_ENABLED)).thenReturn(true);
        when(webhook.webhookUrl()).thenReturn("https://hooks.example.com/weekly");
        when(webhook.signingSecret()).thenReturn("");
        when(mail.isConfigured()).thenReturn(false);
        when(auditLog.countByOperationTypeAndTimestampGreaterThanEqual(anyString(), any())).thenReturn(0L);
        when(gate.overview(any())).thenReturn(new SecurityOverview.Overview(List.of(), 0, 0, 0, 0, 0));
        when(issues.findAll(ArgumentMatchers.<Specification<IssueEntity>>any())).thenReturn(List.of());

        digest = new PostureDigestService(
                settings, gate, sla, issues, auditLog, audit, webhook, mail, post,
                Clock.fixed(WEDNESDAY, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("a send that worked is recorded, against the Monday of its week")
    void aSuccessIsRecorded() {
        assertThat(digest.runOnce()).isTrue();

        ArgumentCaptor<AuditLogService.Record> recorded = ArgumentCaptor.captor();
        verify(audit).record(recorded.capture());
        assertThat(recorded.getValue().operation()).isEqualTo(AuditOperation.POSTURE_DIGEST_SENT);
        // The Monday, not the day it happened: the entry is also the answer to "has one gone out
        // this week", and dating it by the send would make that question depend on the weekday.
        assertThat(recorded.getValue().resourceId()).isEqualTo("2026-08-17");
        // No actor — nobody asked for this one, and inventing a "system" user would put a person
        // who does not exist into a compliance report.
        assertThat(recorded.getValue().userId()).isNull();
    }

    @Test
    @DisplayName("a send that failed records nothing, so the next tick tries again")
    void aFailureIsNotRecorded() {
        doThrow(new OutboundJson.OutboundFailureException("connection refused"))
                .when(post)
                .postSignedJson(anyString(), any(), any(), anyString(), anyString(), any());

        // Swallowed rather than thrown: this runs on the tick beside the purge and the triage
        // expiry, and an unreachable relay must not stop them.
        assertThat(digest.runOnce()).isFalse();

        // The entry is what suppresses the retry. Writing one here would turn one bad Monday into
        // a week with no report and nothing saying so.
        verify(audit, never()).record(any());
    }

    @Test
    @DisplayName("a report already recorded this week is not sent again")
    void oncePerWeek() {
        when(auditLog.countByOperationTypeAndTimestampGreaterThanEqual(
                        eq(AuditOperation.POSTURE_DIGEST_SENT.wireName()), any()))
                .thenReturn(1L);

        assertThat(digest.runOnce()).isFalse();
        verify(post, never()).postSignedJson(anyString(), any(), any(), anyString(), anyString(), any());
    }

    @Test
    @DisplayName("switched off, nothing is built and nothing is asked of the database")
    void offMeansOff() {
        when(settings.isEnabled(Setting.DIGEST_ENABLED)).thenReturn(false);

        assertThat(digest.runOnce()).isFalse();
        // Checked before the log is consulted: a disabled feature should cost a deployment nothing
        // per hour, and this is the cheap half of that.
        verify(auditLog, never()).countByOperationTypeAndTimestampGreaterThanEqual(anyString(), any());
    }
}
