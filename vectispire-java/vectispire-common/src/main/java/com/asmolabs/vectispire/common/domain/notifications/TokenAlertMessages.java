package com.asmolabs.vectispire.common.domain.notifications;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A {@link TokenAlert} as each channel takes it: the generic webhook's JSON, Slack's blocks, a Teams card, a Discord
 * embed, a mail.
 *
 * <p><b>Not the scan delta's shapes.</b> {@link NotificationPayload} is what a scan changed — a target, a scan
 * number, counts of issues — and an alert about a token has none of them; bent into it, it would be a message with
 * {@code scan_id: 0} that a receiver's rules read as a scan. The generic webhook carries {@code event:
 * "token_state_changed"} instead, which a scan delta never has.
 *
 * <p><b>The connection's name is an administrator's text</b>, and in Slack's {@code mrkdwn}, Discord's markdown or
 * an Adaptive Card it would be markup: every rendering goes through {@link ChatText}, as the scan delta's values do.
 */
public final class TokenAlertMessages {

    private TokenAlertMessages() {}

    /** Told apart from a scan delta by this field, which a scan delta never carries. */
    public static final String EVENT = "token_state_changed";

    private static final int SLACK_HEADER = 150;

    /**
     * The generic webhook's body: the sentence first as {@code text}, so a chat receiver that reads only that field
     * shows something readable, then the facts a receiver's rules can test.
     */
    public static Map<String, Object> webhook(TokenAlert alert, String messageId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("text", alert.sentence());
        body.put("event", EVENT);
        body.put("credential", alert.credential().wireName());
        body.put("name", TokenAlert.oneLine(alert.name()));
        body.put("reference", alert.reference());
        body.put("state", alert.notice().wireName());
        body.put("previous_state", alert.previous().wireName());
        body.put("signature_id", alert.signal().signatureId());
        body.put("expires_at", instant(alert.expiresAt()));
        body.put("refused_status", alert.refusedStatus());
        body.put("refused_since", instant(alert.refusedSince()));
        body.put("observed_at", instant(alert.observedAt()));
        body.put("message_id", messageId);
        return body;
    }

    public static Map<String, Object> slack(TokenAlert alert, String publicUrl) {
        List<Map<String, Object>> blocks = new ArrayList<>();
        // Without the connection's name, which the section below carries escaped: a header is plain text, with no
        // escape of its own. And within 150 characters, past which Slack refuses the whole message.
        String headline = alert.anonymousHeadline();
        blocks.add(Map.of("type", "header", "text", Map.of("type", "plain_text",
                "text", headline.length() <= SLACK_HEADER ? headline : headline.substring(0, SLACK_HEADER - 1) + "…",
                "emoji", true)));
        blocks.add(Map.of("type", "section",
                "text", Map.of("type", "mrkdwn", "text", ChatText.slack(alert.sentence()))));
        link(alert, publicUrl).ifPresent(url -> blocks.add(Map.of(
                "type", "actions",
                "elements", List.of(Map.of(
                        "type", "button",
                        "text", Map.of("type", "plain_text", "text", "Open in Vectispire", "emoji", true),
                        "url", url)))));

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("text", ChatText.slack(alert.sentence()));
        root.put("blocks", blocks);
        return root;
    }

    /** An Adaptive Card in the workflow's attachment envelope — see {@link TeamsCard} for why that envelope. */
    public static Map<String, Object> teams(TokenAlert alert, String publicUrl) {
        List<Map<String, Object>> body = new ArrayList<>();
        body.add(text(ChatText.teams(alert.headline()), "bolder", "medium",
                alert.notice().stopped() ? "attention" : alert.notice() == TokenAlert.Notice.EXPIRES_SOON ? "warning" : "good"));
        body.add(text(ChatText.teams(alert.sentence()), "default", "default", "default"));

        Map<String, Object> card = new LinkedHashMap<>();
        card.put("type", "AdaptiveCard");
        card.put("$schema", "http://adaptivecards.io/schemas/adaptive-card.json");
        card.put("version", "1.4");
        card.put("body", body);
        link(alert, publicUrl).ifPresent(url -> card.put("actions", List.of(Map.of(
                "type", "Action.OpenUrl", "title", "Open in Vectispire", "url", url))));

        return Map.of(
                "type", "message",
                "attachments", List.of(Map.of(
                        "contentType", "application/vnd.microsoft.card.adaptive",
                        "contentUrl", "",
                        "content", card)));
    }

    public static Map<String, Object> discord(TokenAlert alert, String publicUrl) {
        Map<String, Object> embed = new LinkedHashMap<>();
        embed.put("title", ChatText.discord(alert.headline()));
        embed.put("description", ChatText.discord(alert.sentence()));
        embed.put("color", alert.notice().stopped() ? 0xDC2626
                : alert.notice() == TokenAlert.Notice.EXPIRES_SOON ? 0xD97706 : 0x059669);
        embed.put("timestamp", instant(alert.observedAt()));
        link(alert, publicUrl).ifPresent(url -> embed.put("url", url));
        embed.put("footer", Map.of("text", "Vectispire DevSecOps Platform"));

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("username", "Vectispire Security");
        root.put("embeds", List.of(embed));
        // Nothing this message says may ping anybody, whatever a connection's name managed to spell.
        root.put("allowed_mentions", Map.of("parse", List.of()));
        return root;
    }

    /** Plain text, for the reasons {@link MailMessage} gives; the subject is the headline, on one line. */
    public static MailMessage.Content mail(TokenAlert alert, String publicUrl, String messageId) {
        List<String> lines = new ArrayList<>();
        lines.add(alert.sentence());
        lines.add("");
        lines.add("State:     " + alert.notice().wireName() + " (was " + alert.previous().wireName() + ")");
        if (alert.expiresAt() != null) {
            lines.add("Expiry:    " + alert.expiresAt());
        }
        if (alert.refusedStatus() != null) {
            lines.add("Refused:   HTTP " + alert.refusedStatus() + " since " + alert.refusedSince());
        }
        lines.add("Noticed:   " + alert.observedAt());
        link(alert, publicUrl).ifPresent(url -> {
            lines.add("");
            lines.add(url);
        });
        lines.add("");
        lines.add("Message " + messageId);
        return new MailMessage.Content(alert.headline(), String.join("\n", lines));
    }

    private static java.util.Optional<String> link(TokenAlert alert, String publicUrl) {
        if (publicUrl == null || publicUrl.isBlank()) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(publicUrl.replaceAll("/+$", "") + alert.credential().screen());
    }

    private static String instant(Instant value) {
        return value == null ? null : value.toString();
    }

    private static Map<String, Object> text(String value, String weight, String size, String colour) {
        Map<String, Object> block = new LinkedHashMap<>();
        block.put("type", "TextBlock");
        block.put("text", value);
        block.put("weight", weight);
        block.put("size", size);
        block.put("color", colour);
        block.put("wrap", true);
        return block;
    }
}
