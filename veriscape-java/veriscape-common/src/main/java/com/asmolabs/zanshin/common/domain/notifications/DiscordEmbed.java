package com.asmolabs.zanshin.common.domain.notifications;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds Discord Webhook Rich Embed JSON payloads.
 */
public final class DiscordEmbed {

    private DiscordEmbed() {}

    public static Map<String, Object> of(NotificationPayload payload, String publicUrl) {
        // Color calculation (Red: 0xDC2626, Amber: 0xD97706, Green: 0x059669)
        int color = 0x059669;
        if (payload.kevCount() > 0 || payload.issues().stream().anyMatch(i -> "critical".equalsIgnoreCase(i.severity()))) {
            color = 0xDC2626; // Red
        } else if (payload.newCount() > 0 || payload.reopenedCount() > 0) {
            color = 0xD97706; // Amber
        }

        Map<String, Object> embed = new LinkedHashMap<>();
        embed.put("title", "🛡️ Zanshin: " + payload.target() + " (Scan #" + payload.scanId() + ")");
        embed.put("description", payload.text());
        embed.put("color", color);
        embed.put("timestamp", Instant.now().toString());

        if (publicUrl != null && !publicUrl.isBlank()) {
            embed.put("url", publicUrl.replaceAll("/+$", "") + "/issues");
        }

        List<Map<String, Object>> fields = new ArrayList<>();
        fields.add(Map.of("name", "New Issues", "value", String.valueOf(payload.newCount()), "inline", true));
        fields.add(Map.of("name", "Reopened", "value", String.valueOf(payload.reopenedCount()), "inline", true));
        fields.add(Map.of("name", "Resolved", "value", String.valueOf(payload.resolvedCount()), "inline", true));
        if (payload.kevCount() > 0) {
            fields.add(Map.of("name", "🚨 CISA KEV Exploited", "value", String.valueOf(payload.kevCount()), "inline", true));
        }

        // Add top issues field
        if (!payload.issues().isEmpty()) {
            StringBuilder issuesSb = new StringBuilder();
            for (NotificationPayload.Detail issue : payload.issues()) {
                String cve = issue.identifier() != null ? issue.identifier() : issue.type();
                String pkg = issue.packageName() != null ? " (" + issue.packageName() + ")" : "";
                String fix = issue.fixVersions() != null ? " → fix: " + issue.fixVersions() : "";
                issuesSb.append(String.format("• **[%s]** %s%s%s\n",
                        issue.severity() != null ? issue.severity().toUpperCase() : "FINDING",
                        cve, pkg, fix));
            }
            if (payload.truncated() > 0) {
                issuesSb.append(String.format("_...and %d more findings_\n", payload.truncated()));
            }
            fields.add(Map.of("name", "Top Findings", "value", issuesSb.toString(), "inline", false));
        }

        embed.put("fields", fields);
        embed.put("footer", Map.of("text", "Zanshin DevSecOps Platform"));

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("username", "Zanshin Security");
        root.put("embeds", List.of(embed));
        return root;
    }
}
