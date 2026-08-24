package com.asmolabs.vectispire.common.domain.notifications;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds Slack Block Kit formatted JSON payloads for rich interactive notifications.
 */
public final class SlackBlockKit {

    private SlackBlockKit() {}

    public static Map<String, Object> of(NotificationPayload payload, String publicUrl) {
        List<Map<String, Object>> blocks = new ArrayList<>();

        // 1. Header
        blocks.add(Map.of(
                "type", "header",
                "text", Map.of("type", "plain_text", "text", "🛡️ Vectispire Security Alert", "emoji", true)));

        // 2. Summary section
        String summaryMarkdown = String.format("*Target:* `%s` (Scan #%d)\n*%s*",
                payload.target(), payload.scanId(), payload.text());
        blocks.add(Map.of(
                "type", "section",
                "text", Map.of("type", "mrkdwn", "text", summaryMarkdown)));

        // 3. Key metrics fields
        List<Map<String, String>> fields = new ArrayList<>();
        fields.add(Map.of("type", "mrkdwn", "text", "*New:* " + payload.newCount()));
        fields.add(Map.of("type", "mrkdwn", "text", "*Reopened:* " + payload.reopenedCount()));
        fields.add(Map.of("type", "mrkdwn", "text", "*Resolved:* " + payload.resolvedCount()));
        if (payload.kevCount() > 0) {
            fields.add(Map.of("type", "mrkdwn", "text", "*🚨 CISA KEV:* " + payload.kevCount()));
        }
        blocks.add(Map.of("type", "section", "fields", fields));

        // 4. Divider
        blocks.add(Map.of("type", "divider"));

        // 5. Issues details
        StringBuilder issuesMd = new StringBuilder("*Vulnerabilities & Findings:*\n");
        for (NotificationPayload.Detail issue : payload.issues()) {
            String emoji = switch (issue.severity() != null ? issue.severity().toLowerCase() : "") {
                case "critical" -> "🔴";
                case "high" -> "🟠";
                case "medium" -> "🟡";
                default -> "⚪";
            };
            String cve = issue.identifier() != null ? issue.identifier() : issue.type();
            String pkg = issue.packageName() != null ? " in `" + issue.packageName() + "`" : "";
            String fix = issue.fixVersions() != null ? " (fix: " + issue.fixVersions() + ")" : "";
            String kev = issue.kev() ? " `[CISA KEV]`" : "";
            issuesMd.append(String.format("%s *%s*%s%s%s\n", emoji, cve, pkg, fix, kev));
        }

        if (payload.truncated() > 0) {
            issuesMd.append(String.format("_...and %d more findings_\n", payload.truncated()));
        }

        blocks.add(Map.of(
                "type", "section",
                "text", Map.of("type", "mrkdwn", "text", issuesMd.toString())));

        // 6. Action button
        if (publicUrl != null && !publicUrl.isBlank()) {
            blocks.add(Map.of(
                    "type", "actions",
                    "elements", List.of(Map.of(
                            "type", "button",
                            "text", Map.of("type", "plain_text", "text", "View in Vectispire", "emoji", true),
                            "url", publicUrl.replaceAll("/+$", "") + "/issues",
                            "style", "primary"))));
        }

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("text", payload.text());
        root.put("blocks", blocks);
        return root;
    }
}
