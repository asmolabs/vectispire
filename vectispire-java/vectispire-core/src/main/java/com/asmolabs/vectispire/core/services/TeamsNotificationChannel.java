package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.notifications.TeamsCard;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Microsoft Teams, through a Power Automate workflow.
 *
 * <p>The card is built in the domain — see {@link TeamsCard}, including why an Adaptive Card in
 * an attachment envelope and not the retired connector's {@code MessageCard}. This class does
 * the two things that need the application: reading the destination, and validating it on every
 * send rather than at queue time, so an operator fixing a typo does not have to re-run a scan.
 */
@Service
public class TeamsNotificationChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(TeamsNotificationChannel.class);

    /** Stored in the outbox, so this string is a data contract. */
    public static final String TYPE = "scan_delta_teams";

    private final SettingsService settings;
    private final OutboundPost post;
    private final ExportProperties deployment;

    public TeamsNotificationChannel(SettingsService settings, OutboundPost post, ExportProperties deployment) {
        this.settings = settings;
        this.post = post;
        this.deployment = deployment;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public boolean isConfigured() {
        return settings.isEnabled(Setting.TEAMS_ENABLED) && !url().isBlank();
    }

    @Override
    public void deliver(NotificationPayload payload) {
        // The same guard the generic webhook uses: a URL resolving to a private address is far
        // more often a server-side request forgery attempt than an intranet endpoint.
        OutboundPolicy policy = settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;

        post.postJson(
                url(),
                // The same address the exports use: a deployment that knows where it lives says
                // so once, and a card with no way back to the backlog ends the conversation where
                // it should start one.
                TeamsCard.of(payload, deployment.publicUrl().orElse(null)),
                policy,
                "Teams webhook URL");

        log.info("Teams notified for scan {}, message {}.", payload.scanId(), payload.messageId());
    }

    private String url() {
        return settings.get(Setting.TEAMS_WEBHOOK_URL).trim();
    }
}
