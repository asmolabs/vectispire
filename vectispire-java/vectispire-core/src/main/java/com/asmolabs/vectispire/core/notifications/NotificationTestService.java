package com.asmolabs.vectispire.core.notifications;

import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.outbox.NotificationChannel;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
    private final Clock clock;

    public NotificationTestService(List<NotificationChannel> channels, SettingsService settings, Clock clock) {
        this.channels = channels;
        this.settings = settings;
        this.clock = clock;
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
                case "scan_delta" -> "Generic webhook / SIEM";
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
                .filter(c -> c.type().equalsIgnoreCase(type) || c.type().endsWith("_" + type.toLowerCase(Locale.ROOT)))
                .findFirst();

        if (match.isEmpty()) {
            return new NotificationTestResult(type, false, "Unknown notification channel type: " + type, clock.instant());
        }

        NotificationChannel channel = match.get();
        if (!channel.isConfigured()) {
            return new NotificationTestResult(channel.type(), false, "Channel is not configured with a destination URL/recipient.", clock.instant());
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
                "test-msg-" + clock.millis());

        // **Delivered or not, and nothing of why.** The answer quoted the sender's own words to the
        // security lead who pressed the button — "Connection refused", a timeout, "HTTP 404", and with
        // private destinations refused, the guard's sentence naming the internal address a host name
        // resolved to. Pointing a channel at host after host made the button a scanner of the internal
        // network. The cause goes to the server log, where an administrator reads it — as the SIEM
        // export's test does.
        try {
            channel.deliver(testPayload);
            return new NotificationTestResult(channel.type(), true, "Test payload successfully dispatched to " + channel.type(), clock.instant());
        } catch (Exception e) {
            log.warn("Notification test failed for {}: {}", channel.type(), e.getMessage());
            return new NotificationTestResult(channel.type(), false, NOT_DELIVERED, clock.instant());
        }
    }

    static final String NOT_DELIVERED = "The test message was not delivered: the destination is refused by the "
            + "outbound policy, could not be reached, or did not accept it. The cause is in the server log.";

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
