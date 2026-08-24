package com.asmolabs.vectispire.common.domain.notifications;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A scan's delta as a card Microsoft Teams will render.
 *
 * <h2>A Workflow, not a connector</h2>
 *
 * <p>Teams had two ways to receive a webhook and only one is left. The old <em>Office 365
 * connector</em> took a {@code MessageCard} and was retired; the supported path is a <b>Power
 * Automate workflow</b> — "when a Teams webhook request is received" — which takes an
 * <b>Adaptive Card</b> wrapped in an attachment envelope. That envelope is what this builds, and
 * getting it wrong is not a rendering problem: a workflow handed a bare card posts nothing and
 * reports success, which is the failure this whole codebase keeps naming.
 *
 * <h2>Why the card is built here and not by the operator</h2>
 *
 * <p>The generic payload already reaches Teams through a flow — the operator maps the JSON to a
 * card themselves. That works and asks somebody to rebuild, in a low-code designer, the mapping
 * that changes every time a field is added here. The card belongs with the payload it renders.
 *
 * <p>Version 1.4 rather than the latest: Teams lags the Adaptive Card specification, and a card
 * using something the client does not know renders as an empty block rather than failing
 * visibly.
 */
public final class TeamsCard {

    private TeamsCard() {}

    /** Named in the attachment, and the only value Teams accepts for an adaptive card. */
    private static final String ADAPTIVE_CARD = "application/vnd.microsoft.card.adaptive";

    /**
     * The colours Teams knows.
     *
     * <p>Adaptive Cards have no palette, only these names — so severity is expressed with the
     * four the client understands rather than with a hexadecimal that would be ignored.
     */
    private static String colourOf(String severity) {
        return switch (severity == null ? "" : severity.toLowerCase(java.util.Locale.ROOT)) {
            case "critical", "high" -> "attention";
            case "medium" -> "warning";
            case "low", "negligible" -> "default";
            default -> "default";
        };
    }

    /**
     * @param publicUrl the instance's public base URL, or null. A card without a way back to the
     *     backlog is a card that ends the conversation where it should start one — but an
     *     unreachable link is worse than none, so the button appears only when the deployment
     *     knows its own address.
     */
    public static Map<String, Object> of(NotificationPayload payload, String publicUrl) {
        List<Map<String, Object>> body = new ArrayList<>();

        body.add(text(payload.text(), "bolder", "large", "default", false));
        body.add(text(
                payload.target() + "  ·  scan #" + payload.scanId(),
                "default", "small", "default", true));
        body.add(facts(payload));

        for (NotificationPayload.Detail issue : payload.issues()) {
            body.add(text(issueLine(issue), "bolder", "default", colourOf(issue.severity()), false));
            String context = context(issue);
            if (!context.isEmpty()) {
                body.add(text(context, "default", "small", "default", true));
            }
        }

        if (payload.truncated() > 0) {
            // Said, never silently dropped: a card listing ten of four hundred reads as a scan
            // that found ten.
            body.add(text("and " + payload.truncated() + " more", "default", "small", "default", true));
        }

        Map<String, Object> card = new LinkedHashMap<>();
        card.put("type", "AdaptiveCard");
        card.put("$schema", "http://adaptivecards.io/schemas/adaptive-card.json");
        card.put("version", "1.4");
        card.put("body", body);
        if (publicUrl != null && !publicUrl.isBlank()) {
            card.put("actions", List.of(Map.of(
                    "type", "Action.OpenUrl",
                    "title", "Open in Vectispire",
                    "url", trimTrailingSlash(publicUrl) + "/issues")));
        }

        return Map.of(
                "type", "message",
                "attachments", List.of(Map.of(
                        "contentType", ADAPTIVE_CARD,
                        // Required by the envelope and always null for an inline card. Teams
                        // rejects the attachment outright when the key is missing.
                        "contentUrl", "",
                        "content", card)));
    }

    private static Map<String, Object> facts(NotificationPayload payload) {
        List<Map<String, String>> facts = new ArrayList<>();
        facts.add(fact("New", String.valueOf(payload.newCount())));
        facts.add(fact("Reopened", String.valueOf(payload.reopenedCount())));
        facts.add(fact("Resolved", String.valueOf(payload.resolvedCount())));
        if (payload.kevCount() > 0) {
            // Only when there are any: a row reading "Actively exploited: 0" trains the eye to
            // skip the line that matters on the day it is not zero.
            facts.add(fact("Actively exploited", String.valueOf(payload.kevCount())));
        }
        facts.add(fact("Threshold", payload.minSeverity()));

        return Map.of("type", "FactSet", "facts", facts);
    }

    private static Map<String, String> fact(String title, String value) {
        return Map.of("title", title, "value", value);
    }

    private static String issueLine(NotificationPayload.Detail issue) {
        String severity = issue.severity() == null ? "unknown" : issue.severity();
        return (issue.kev() ? "[exploited] " : "")
                + severity.toUpperCase(java.util.Locale.ROOT)
                + " · " + (issue.identifier() == null ? issue.type() : issue.identifier());
    }

    /** Where it is and what fixes it — the two things a reader acts on. */
    private static String context(NotificationPayload.Detail issue) {
        List<String> parts = new ArrayList<>();
        if (issue.packageName() != null && !issue.packageName().isBlank()) {
            parts.add(issue.packageName());
        }
        if (issue.filePath() != null && !issue.filePath().isBlank()) {
            parts.add(issue.filePath());
        }
        if (issue.fixVersions() != null && !issue.fixVersions().isBlank()) {
            parts.add("fixed in " + issue.fixVersions());
        }
        return String.join("  ·  ", parts);
    }

    private static Map<String, Object> text(
            String value, String weight, String size, String colour, boolean subtle) {

        Map<String, Object> block = new LinkedHashMap<>();
        block.put("type", "TextBlock");
        block.put("text", value == null ? "" : value);
        block.put("weight", weight);
        block.put("size", size);
        block.put("color", colour);
        block.put("isSubtle", subtle);
        // Without this a long identifier or file path is truncated to one line, and the path is
        // the half of the message a reader acts on.
        block.put("wrap", true);
        return block;
    }

    private static String trimTrailingSlash(String url) {
        return url.replaceAll("/+$", "");
    }
}
