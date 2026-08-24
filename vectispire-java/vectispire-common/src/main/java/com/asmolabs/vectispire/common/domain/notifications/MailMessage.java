package com.asmolabs.vectispire.common.domain.notifications;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A scan's delta as an e-mail.
 *
 * <h2>Plain text, and that is a decision</h2>
 *
 * <p>An HTML message would look better in three clients and worse in the rest, and it would mean
 * escaping — into a body assembled from an identifier, a file path and a fix version, all of
 * which come from the audited repository or from an upstream advisory. Text has no escaping to
 * get wrong, renders identically everywhere, and survives being quoted into a ticket, which is
 * what actually happens to these messages.
 *
 * <h2>The subject carries the verdict</h2>
 *
 * <p>A mailbox shows a subject and nothing else until somebody opens it. "Vectispire" alone is a
 * message somebody learns to leave unread; the target and the counts are what decide whether it
 * is opened now or after lunch.
 */
public final class MailMessage {

    private MailMessage() {}

    public record Content(String subject, String body) {}

    public static Content of(NotificationPayload payload, String publicUrl) {
        return new Content(subjectOf(payload), bodyOf(payload, publicUrl));
    }

    private static String subjectOf(NotificationPayload payload) {
        List<String> counts = new ArrayList<>();
        if (payload.newCount() > 0) {
            counts.add(payload.newCount() + " new");
        }
        if (payload.reopenedCount() > 0) {
            counts.add(payload.reopenedCount() + " reopened");
        }
        // The exploited count leads when there is one: it is the only figure here that changes
        // what somebody does this afternoon.
        String lead = payload.kevCount() > 0 ? "[exploited] " : "";
        String what = counts.isEmpty() ? "scan reported" : String.join(", ", counts);

        return lead + "Vectispire · " + payload.target() + " · " + what;
    }

    private static String bodyOf(NotificationPayload payload, String publicUrl) {
        List<String> lines = new ArrayList<>();
        lines.add(payload.text());
        lines.add("");
        lines.add("Target:    " + payload.target());
        lines.add("Scan:      #" + payload.scanId());
        lines.add("New:       " + payload.newCount());
        lines.add("Reopened:  " + payload.reopenedCount());
        lines.add("Resolved:  " + payload.resolvedCount());
        if (payload.kevCount() > 0) {
            lines.add("Actively exploited: " + payload.kevCount());
        }
        lines.add("Threshold: " + payload.minSeverity());

        if (!payload.issues().isEmpty()) {
            lines.add("");
            lines.add("Findings");
            lines.add("--------");
            for (NotificationPayload.Detail issue : payload.issues()) {
                lines.add(line(issue));
            }
            if (payload.truncated() > 0) {
                // Named rather than dropped: a list of ten out of four hundred reads as a scan
                // that found ten.
                lines.add("… and " + payload.truncated() + " more, not listed here.");
            }
        }

        if (publicUrl != null && !publicUrl.isBlank()) {
            lines.add("");
            lines.add(publicUrl.replaceAll("/+$", "") + "/issues");
        }

        lines.add("");
        // The identifier a receiver deduplicates on: delivery is at-least-once, so the same
        // message can arrive twice and the reader needs to be able to tell.
        lines.add("Message " + payload.messageId());
        return String.join("\n", lines);
    }

    private static String line(NotificationPayload.Detail issue) {
        StringBuilder line = new StringBuilder("  ");
        line.append(issue.kev() ? "[exploited] " : "");
        line.append((issue.severity() == null ? "unknown" : issue.severity()).toUpperCase(Locale.ROOT));
        line.append("  ").append(issue.identifier() == null ? issue.type() : issue.identifier());

        if (issue.packageName() != null && !issue.packageName().isBlank()) {
            line.append("  ").append(issue.packageName());
        }
        if (issue.filePath() != null && !issue.filePath().isBlank()) {
            line.append("  ").append(issue.filePath());
        }
        if (issue.fixVersions() != null && !issue.fixVersions().isBlank()) {
            line.append("  (fixed in ").append(issue.fixVersions()).append(')');
        }
        return line.toString();
    }
}
