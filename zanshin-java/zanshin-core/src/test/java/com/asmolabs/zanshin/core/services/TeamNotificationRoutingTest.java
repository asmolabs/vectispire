package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.persistence.TeamWebhookEntity;
import com.asmolabs.zanshin.core.repositories.TeamWebhooks;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Where a notification is sent, once teams have their own channels.
 *
 * <p><b>The leak this closes.</b> Visibility decides what an account reads in the interface and
 * decides nothing about the channel Zanshin posts to. With one global webhook, a deployment that
 * carefully restricted its screens still announced every team's vulnerabilities where everybody
 * reads — the partitioning leaking through Slack.
 *
 * <p>What is asserted here is the destination, which is the part no payload test can see: the
 * message and its contents are the same either way, and only the URL differs.
 */
@DisplayName("where a notification goes")
class TeamNotificationRoutingTest {

    private static final String GLOBAL = "https://hooks.example.com/global";
    private static final String TEAM = "https://hooks.example.com/backend";

    private SettingsService settings;
    private OutboundPost post;
    private TeamWebhooks webhooks;
    private NotificationService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        post = mock(OutboundPost.class);
        webhooks = mock(TeamWebhooks.class);
        service = new NotificationService(settings, post, webhooks);

        when(settings.get(Setting.WEBHOOK_URL)).thenReturn(GLOBAL);
        when(settings.get(Setting.NOTIFICATION_MIN_SEVERITY)).thenReturn("high");
        when(settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)).thenReturn(false);
    }

    @Test
    @DisplayName("a message with no team goes to the global channel")
    void theGlobalChannelIsTheDefault() {
        service.deliver(payload(), null);

        assertThat(destination()).isEqualTo(GLOBAL);
    }

    @Test
    @DisplayName("a message for a team goes to that team's channel, not the global one")
    void aTeamsMessageGoesToItsOwnChannel() {
        when(webhooks.findById(7L)).thenReturn(Optional.of(new TeamWebhookEntity(7L, TEAM)));

        service.deliver(payload(), 7L);

        assertThat(destination()).isEqualTo(TEAM);
    }

    @Test
    @DisplayName("the URL is read now, not when the message was queued")
    void theDestinationIsResolvedLate() {
        // The property that makes fixing a typo enough: an operator corrects the channel and the
        // queued notifications flush to the corrected one, with no re-scan. Storing the resolved
        // URL on the row would have frozen the mistake.
        when(webhooks.findById(7L)).thenReturn(Optional.of(new TeamWebhookEntity(7L, "https://typo.example.com/x")));
        service.deliver(payload(), 7L);
        assertThat(destination()).isEqualTo("https://typo.example.com/x");

        when(webhooks.findById(7L)).thenReturn(Optional.of(new TeamWebhookEntity(7L, TEAM)));
        service.deliver(payload(), 7L);
        assertThat(destination()).isEqualTo(TEAM);
    }

    @Test
    @DisplayName("a destination that no longer exists is permanent, not a retry")
    void aDeletedTeamIsNotRetried() {
        when(webhooks.findById(7L)).thenReturn(Optional.empty());

        // Its own exception type, because the relay treats the two differently: an unreachable
        // Slack deserves the twelve retries the backoff policy grants, a team somebody deleted
        // deserves none — nothing about waiting brings it back, and twelve attempts would fill
        // the log with an error nobody can act on.
        assertThatThrownBy(() -> service.deliver(payload(), 7L))
                .isInstanceOf(NotificationService.GoneDestinationException.class)
                .hasMessageContaining("no longer has a webhook");
    }

    @Test
    @DisplayName("a team whose channel was cleared is gone, not empty")
    void anEmptyUrlIsGoneToo() {
        // A blank row reaching the sender would be posted to "", which fails as an unreadable URL
        // and gets retried eleven more times. The same answer as a deleted team, because it is the
        // same situation: nobody is listening there any more.
        when(webhooks.findById(7L)).thenReturn(Optional.of(new TeamWebhookEntity(7L, "   ")));

        assertThatThrownBy(() -> service.deliver(payload(), 7L))
                .isInstanceOf(NotificationService.GoneDestinationException.class);
    }

    @Test
    @DisplayName("clearing the global URL does not silently drop its queued messages")
    void aClearedGlobalUrlIsAlsoGone() {
        when(settings.get(Setting.WEBHOOK_URL)).thenReturn("");

        assertThatThrownBy(() -> service.deliver(payload(), null))
                .isInstanceOf(NotificationService.GoneDestinationException.class)
                .hasMessageContaining("global webhook URL has been cleared");
    }

    @Test
    @DisplayName("notifications are enabled by a team channel alone, with no global one")
    void teamChannelsAloneAreEnough() {
        when(settings.get(Setting.WEBHOOK_URL)).thenReturn("");
        when(webhooks.count()).thenReturn(1L);

        // A deployment that gives each team its own channel and sets no global one is a reasonable
        // configuration. Reading the global URL alone would have made it a configuration in which
        // nothing is ever built or queued — the channels set, the screen saying so, and no message
        // in existence.
        assertThat(service.isEnabled()).isTrue();

        when(webhooks.count()).thenReturn(0L);
        assertThat(service.isEnabled()).isFalse();
    }

    private String destination() {
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(post, org.mockito.Mockito.atLeastOnce())
                .postJson(url.capture(), any(), any(), anyString());
        return url.getValue();
    }

    private static NotificationPayload payload() {
        return NotificationPayload.of(new NotificationPayload.Delta(
                "org/project", 12, List.of(), List.of(), 0, com.asmolabs.zanshin.common.domain.issues.Severity.HIGH));
    }
}
