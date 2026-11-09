package com.asmolabs.vectispire.core.notifications;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Credential;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Notice;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.access.TeamChannels;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.notifications.internal.AlertChannel;
import com.asmolabs.vectispire.core.notifications.internal.DiscordNotificationChannel;
import com.asmolabs.vectispire.core.notifications.internal.SlackNotificationChannel;
import com.asmolabs.vectispire.core.notifications.internal.TeamsNotificationChannel;
import com.asmolabs.vectispire.core.notifications.internal.TokenAlertAudit;
import com.asmolabs.vectispire.core.notifications.internal.TokenAlertDelivery;
import com.asmolabs.vectispire.core.notifications.internal.TokenAlerts;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.settings.ExportProperties;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Where a token's change of state is sent, and under which rule: each channel's own destination, read at the send,
 * behind the same private-address switch as a scan's delta.
 *
 * <p>What the message says is {@code TokenAlertTest}'s; this is the destination and the rule, which no payload test
 * can see, and the routing from a queued row to its channel.
 */
@DisplayName("a token's change of state, on each channel")
class TokenAlertChannelsTest {

    private static final String WEBHOOK = "https://hooks.example.com/global";
    private static final String SLACK = "https://hooks.slack.example.com/T0/B0/x";
    private static final String TEAMS = "https://prod.workflows.example.com/teams";
    private static final String DISCORD = "https://discord.example.com/api/webhooks/1/x";

    private SettingsService settings;
    private OutboundPost post;
    private JavaMailSender mailer;
    private NotificationService webhook;
    private SlackNotificationChannel slack;
    private TeamsNotificationChannel teams;
    private DiscordNotificationChannel discord;
    private MailNotificationChannel mail;

    private final TokenAlert alert = new TokenAlert(Credential.FORGE_CONNECTION, UUID.randomUUID().toString(),
            "Platform GitLab", "GitLab self-managed or Dedicated at https://gitlab.example.com", Notice.EXPIRED,
            Notice.EXPIRES_SOON, Instant.parse("2026-10-27T00:00:00Z"), null, null, Instant.parse("2026-10-27T01:00:00Z"));

    private com.asmolabs.vectispire.core.settings.Integrations registry;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        post = mock(OutboundPost.class);
        mailer = mock(JavaMailSender.class);
        when(settings.get(any())).thenReturn("");
        when(settings.get(Setting.WEBHOOK_URL)).thenReturn(WEBHOOK);
        when(settings.get(Setting.SLACK_WEBHOOK_URL)).thenReturn(SLACK);
        when(settings.get(Setting.TEAMS_WEBHOOK_URL)).thenReturn(TEAMS);
        when(settings.get(Setting.DISCORD_WEBHOOK_URL)).thenReturn(DISCORD);
        when(settings.get(Setting.MAIL_RECIPIENTS)).thenReturn("secops@example.com, cto@example.com");
        when(settings.isEnabled(Setting.TEAMS_ENABLED)).thenReturn(true);
        ExportProperties deployment = new ExportProperties(Optional.of("https://vectispire.example.com"), "Vectispire", "0");

        Clock clock = Clock.fixed(Instant.parse("2026-10-27T01:00:00Z"), ZoneOffset.UTC);
        registry = com.asmolabs.vectispire.core.settings.EnabledIntegrations.all();
        webhook = new NotificationService(settings, post, mock(TeamChannels.class), mock(EncryptionService.class), registry, clock);
        slack = new SlackNotificationChannel(settings, post, deployment, registry);
        teams = new TeamsNotificationChannel(settings, post, deployment, registry);
        discord = new DiscordNotificationChannel(settings, post, deployment, clock, registry);
        mail = new MailNotificationChannel(settings, Optional.of(mailer), deployment, "vectispire@example.com", registry);
    }

    @Test
    @DisplayName("the generic webhook: the global URL, signed as a scan's delta, the event named")
    void theWebhook() {
        webhook.deliverAlert(alert, "m-1");

        ArgumentCaptor<Object> body = ArgumentCaptor.forClass(Object.class);
        verify(post).postSignedJson(eq(WEBHOOK), body.capture(), eq(OutboundPolicy.PUBLIC_ONLY), anyString(), eq(""), any());
        assertThat(body.getValue()).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                .containsEntry("event", "token_state_changed")
                .containsEntry("state", "expired")
                .containsEntry("name", "Platform GitLab")
                .containsEntry("message_id", "m-1");
    }

    @Test
    @DisplayName("Slack: its own URL")
    void slack() {
        slack.deliverAlert(alert, "m-1");

        verify(post).postJson(eq(SLACK), any(Map.class), eq(OutboundPolicy.PUBLIC_ONLY), anyString());
    }

    @Test
    @DisplayName("Teams: its own URL, and only while it is switched on")
    void teams() {
        teams.deliverAlert(alert, "m-1");
        verify(post).postJson(eq(TEAMS), any(Map.class), eq(OutboundPolicy.PUBLIC_ONLY), anyString());

        when(settings.isEnabled(Setting.TEAMS_ENABLED)).thenReturn(false);
        assertThat(teams.isConfigured()).isFalse();
    }

    @Test
    @DisplayName("Discord: its own URL")
    void discord() {
        discord.deliverAlert(alert, "m-1");

        verify(post).postJson(eq(DISCORD), any(Map.class), eq(OutboundPolicy.PUBLIC_ONLY), anyString());
    }

    @Test
    @DisplayName("mail: the configured recipients, the headline as the subject, the message id in the body")
    void mail() {
        mail.deliverAlert(alert, "m-1");

        ArgumentCaptor<SimpleMailMessage> sent = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailer).send(sent.capture());
        assertThat(sent.getValue().getTo()).containsExactly("secops@example.com", "cto@example.com");
        assertThat(sent.getValue().getSubject()).isEqualTo("Vectispire · forge connection \"Platform GitLab\" · token expired");
        assertThat(sent.getValue().getText()).contains("expired on 2026-10-27T00:00:00Z").contains("Message m-1")
                .contains("https://vectispire.example.com/forge-connections");
    }

    @Test
    @DisplayName("a private destination is reached only when the administrator's switch says so, on every channel")
    void thePrivateAddressRuleHolds() {
        when(settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)).thenReturn(true);

        webhook.deliverAlert(alert, "m-1");
        slack.deliverAlert(alert, "m-1");
        teams.deliverAlert(alert, "m-1");
        discord.deliverAlert(alert, "m-1");

        verify(post).postSignedJson(eq(WEBHOOK), any(), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString(), anyString(), any());
        verify(post).postJson(eq(SLACK), any(Map.class), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString());
        verify(post).postJson(eq(TEAMS), any(Map.class), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString());
        verify(post).postJson(eq(DISCORD), any(Map.class), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString());
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"webhook", "slack", "teams", "discord", "mail"})
    @DisplayName("a queued row reaches the channel it names, and that one alone")
    void aRowReachesItsChannel(String key) throws Exception {
        List<AlertChannel> channels = List.of(webhook, slack, teams, discord, mail);
        ObjectMapper json = new ObjectMapper().registerModule(new JavaTimeModule());
        String payload = json.writeValueAsString(new TokenAlertDelivery.Queued(key, alert));

        new TokenAlertDelivery(channels, json).deliver(UUID.randomUUID(), payload);

        verify(post, key.equals("webhook") ? org.mockito.Mockito.times(1) : never())
                .postSignedJson(anyString(), any(), any(), anyString(), anyString(), any());
        verify(post, key.equals("slack") ? org.mockito.Mockito.times(1) : never()).postJson(eq(SLACK), any(), any(), anyString());
        verify(post, key.equals("teams") ? org.mockito.Mockito.times(1) : never()).postJson(eq(TEAMS), any(), any(), anyString());
        verify(post, key.equals("discord") ? org.mockito.Mockito.times(1) : never())
                .postJson(eq(DISCORD), any(), any(), anyString());
        verify(mailer, key.equals("mail") ? org.mockito.Mockito.times(1) : never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("a channel cleared while its alert waited is gone, not retried; an unknown one is an error")
    void goneAndUnknownChannels() throws Exception {
        ObjectMapper json = new ObjectMapper().registerModule(new JavaTimeModule());
        TokenAlertDelivery delivery = new TokenAlertDelivery(List.of(webhook, slack, teams, discord, mail), json);
        when(settings.get(Setting.SLACK_WEBHOOK_URL)).thenReturn("");

        assertThatThrownBy(() -> delivery.deliver(UUID.randomUUID(),
                json.writeValueAsString(new TokenAlertDelivery.Queued("slack", alert))))
                .isInstanceOf(GoneDestinationException.class);
        assertThatThrownBy(() -> delivery.deliver(UUID.randomUUID(),
                json.writeValueAsString(new TokenAlertDelivery.Queued("pager", alert))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("unknown channel");
    }

    @Test
    @DisplayName("the change is queued as its audit entry and once per configured channel, in the caller's transaction")
    void queuedOncePerConfiguredChannel() {
        OutboxService outbox = mock(OutboxService.class);
        when(settings.get(Setting.DISCORD_WEBHOOK_URL)).thenReturn("");

        new TokenAlerts(outbox, List.of(webhook, slack, teams, discord, mail), registry).changed(alert);

        verify(outbox).enqueue(alert, TokenAlertAudit.TYPE);
        ArgumentCaptor<Object> rows = ArgumentCaptor.forClass(Object.class);
        verify(outbox, org.mockito.Mockito.times(4)).enqueue(rows.capture(), eq(TokenAlertDelivery.TYPE));
        assertThat(rows.getAllValues()).map(row -> ((TokenAlertDelivery.Queued) row).channel())
                .containsExactly("webhook", "slack", "teams", "mail");
    }

    @Test
    @DisplayName("a channel switched off is queued no alert, as one without a destination is (decision 0040, lot I6)")
    void aSwitchedOffChannelIsQueuedNothing() {
        OutboxService outbox = mock(OutboxService.class);
        when(registry.isEnabled(com.asmolabs.vectispire.common.domain.integrations.Integration.of(
                com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind.SLACK))).thenReturn(false);

        new TokenAlerts(outbox, List.of(webhook, slack, teams, discord, mail), registry).changed(alert);

        ArgumentCaptor<Object> rows = ArgumentCaptor.forClass(Object.class);
        verify(outbox, org.mockito.Mockito.times(4)).enqueue(rows.capture(), eq(TokenAlertDelivery.TYPE));
        assertThat(rows.getAllValues()).map(row -> ((TokenAlertDelivery.Queued) row).channel())
                .containsExactly("webhook", "teams", "discord", "mail");
    }

    /**
     * Each channel asks the integrations' registry at its own entry (decision 0040, lot I6): switched off, the scan's
     * delta and the alert from the outbox are held — not failed, so the relay counts no attempt — and nothing leaves.
     */
    @Test
    @DisplayName("a channel switched off holds the delta and the alert, and sends nothing: each of the five, each way in")
    void aSwitchedOffChannelSendsNothing() {
        when(registry.isEnabled(any())).thenReturn(false);
        com.asmolabs.vectispire.common.domain.notifications.NotificationPayload payload =
                new com.asmolabs.vectispire.common.domain.notifications.NotificationPayload("text", "target", 1L, 1, 0, 0, 1,
                        "CRITICAL", List.of(), 0, "message-1");

        for (com.asmolabs.vectispire.core.outbox.NotificationChannel channel : List.of(webhook, slack, teams, discord, mail)) {
            assertThatThrownBy(() -> channel.deliver(payload, null)).as(channel.type())
                    .isInstanceOf(com.asmolabs.vectispire.core.outbox.HeldDeliveryException.class)
                    .hasMessageContaining("is disabled on this installation");
        }
        for (AlertChannel channel : List.<AlertChannel>of(webhook, slack, teams, discord, mail)) {
            assertThatThrownBy(() -> channel.deliverAlert(alert, "message-2")).as(channel.alertKey())
                    .isInstanceOf(com.asmolabs.vectispire.core.outbox.HeldDeliveryException.class);
        }
        // Outside the outbox — the weekly report, the reminders — the refusal is the integration's own.
        assertThatThrownBy(() -> mail.sendText("subject", "body"))
                .isInstanceOf(com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException.class);
        assertThatThrownBy(() -> mail.sendTextTo(List.of("a@example.com"), "subject", "body"))
                .isInstanceOf(com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException.class);

        org.mockito.Mockito.verifyNoInteractions(post, mailer);
    }
}
