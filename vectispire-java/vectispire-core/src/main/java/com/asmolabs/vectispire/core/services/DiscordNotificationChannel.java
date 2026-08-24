package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.notifications.DiscordEmbed;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Delivers formatted Rich Embed notifications to Discord Webhooks.
 */
@Service
public class DiscordNotificationChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(DiscordNotificationChannel.class);

    public static final String TYPE = "scan_delta_discord";

    private final SettingsService settings;
    private final OutboundPost post;
    private final ExportProperties deployment;

    public DiscordNotificationChannel(SettingsService settings, OutboundPost post, ExportProperties deployment) {
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
        return !url().isBlank();
    }

    @Override
    public void deliver(NotificationPayload payload) {
        OutboundPolicy policy = settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;

        post.postJson(
                url(),
                DiscordEmbed.of(payload, deployment.publicUrl().orElse(null)),
                policy,
                "Discord webhook URL");

        log.info("Discord notified for scan {}, message {}.", payload.scanId(), payload.messageId());
    }

    private String url() {
        return settings.get(Setting.DISCORD_WEBHOOK_URL).trim();
    }
}
