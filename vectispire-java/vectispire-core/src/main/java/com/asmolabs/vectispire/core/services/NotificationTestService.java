package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service for testing connectivity and inspecting health of all configured notification channels.
 */
@Service
public class NotificationTestService {

    private static final Logger log = LoggerFactory.getLogger(NotificationTestService.class);

    private final List<NotificationChannel> channels;
    private final SettingsService settings;

    public NotificationTestService(List<NotificationChannel> channels, SettingsService settings) {
        this.channels = channels;
        this.settings = settings;
    }

    public record NotificationChannelStatus(
            String type,
            String name,
            String destination,
            boolean configured,
            List<String> supportedEvents) {}

    public record NotificationTestResult(
            String type,
            boolean success,
            String message,
            Instant testedAt) {}

    public List<NotificationChannelStatus> getChannelsStatus() {
        List<NotificationChannelStatus> list = new ArrayList<>();
        List<String> defaultEvents = List.of(
                "GATE_FAILED",
                "CRITICAL_KEV_DETECTED",
                "FOUR_EYES_APPROVAL_REQUIRED",
                "WEEKLY_POSTURE_REPORT");

        for (NotificationChannel channel : channels) {
            String name = switch (channel.type()) {
                case "scan_delta" -> "Webhook Générique / SIEM";
                case "scan_delta_teams" -> "Microsoft Teams (Adaptive Cards)";
                case "scan_delta_slack" -> "Slack (Block Kit)";
                case "scan_delta_discord" -> "Discord (Rich Embeds)";
                case "scan_delta_mail" -> "Email / SMTP";
                default -> channel.type();
            };

            String rawDest = switch (channel.type()) {
                case "scan_delta" -> settings.get(Setting.WEBHOOK_URL);
                case "scan_delta_teams" -> settings.get(Setting.TEAMS_WEBHOOK_URL);
                case "scan_delta_slack" -> settings.get(Setting.SLACK_WEBHOOK_URL);
                case "scan_delta_discord" -> settings.get(Setting.DISCORD_WEBHOOK_URL);
                case "scan_delta_mail" -> settings.get(Setting.MAIL_RECIPIENTS);
                default -> "";
            };

            String masked = maskDestination(rawDest);

            list.add(new NotificationChannelStatus(
                    channel.type(),
                    name,
                    masked,
                    channel.isConfigured(),
                    defaultEvents));
        }

        return list;
    }

    public NotificationTestResult testChannel(String type) {
        Optional<NotificationChannel> match = channels.stream()
                .filter(c -> c.type().equalsIgnoreCase(type) || c.type().endsWith("_" + type.toLowerCase()))
                .findFirst();

        if (match.isEmpty()) {
            return new NotificationTestResult(type, false, "Unknown notification channel type: " + type, Instant.now());
        }

        NotificationChannel channel = match.get();
        if (!channel.isConfigured()) {
            return new NotificationTestResult(channel.type(), false, "Channel is not configured with a destination URL/recipient.", Instant.now());
        }

        NotificationPayload testPayload = new NotificationPayload(
                "🔔 Vectispire Connectivity Test — All systems operational",
                "test-target:main",
                999L,
                1,
                0,
                0,
                1,
                "CRITICAL",
                List.of(new NotificationPayload.Detail(
                        999L,
                        "CVE-2021-44228",
                        "sca",
                        "CRITICAL",
                        true,
                        0.975,
                        "org.apache.logging.log4j:log4j-core",
                        "pom.xml",
                        "2.17.1",
                        null)),
                0,
                "test-msg-" + Instant.now().toEpochMilli());

        try {
            channel.deliver(testPayload);
            return new NotificationTestResult(channel.type(), true, "Test payload successfully dispatched to " + channel.type(), Instant.now());
        } catch (Exception e) {
            log.warn("Notification test failed for {}: {}", channel.type(), e.getMessage());
            return new NotificationTestResult(channel.type(), false, "Delivery failed: " + e.getMessage(), Instant.now());
        }
    }

    private static String maskDestination(String dest) {
        if (dest == null || dest.isBlank()) return "";
        if (dest.contains("@")) { // Email
            return dest;
        }
        if (dest.length() <= 20) {
            return "***";
        }
        return dest.substring(0, 12) + "..." + dest.substring(dest.length() - 8);
    }
}
