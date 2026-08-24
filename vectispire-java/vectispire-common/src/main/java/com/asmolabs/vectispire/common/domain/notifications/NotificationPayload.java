package com.asmolabs.vectispire.common.domain.notifications;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * What a scan changed, formatted for a webhook.
 *
 * <p><b>A generic webhook, not a Slack integration.</b> An HTTP POST with a documented JSON
 * body reaches Slack, Teams through a flow, Discord, Mattermost, an internal bus, or a
 * three-line script. A vendor-specific payload buys prettier formatting in one place at the
 * cost of every other — hence {@code text} first, so chat receivers that read only that field
 * still display something readable.
 *
 * <p>The message is a <b>snapshot</b>: it says what the scan found, not what the issues look
 * like once somebody has triaged half of them.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "text", "target", "scan_id", "new_count", "reopened_count",
    "resolved_count", "kev_count", "min_severity", "issues", "truncated", "message_id"
})
public record NotificationPayload(
        String text,
        String target,
        @JsonProperty("scan_id") long scanId,
        @JsonProperty("new_count") int newCount,
        @JsonProperty("reopened_count") int reopenedCount,
        @JsonProperty("resolved_count") int resolvedCount,
        @JsonProperty("kev_count") long kevCount,
        @JsonProperty("min_severity") String minSeverity,
        List<Detail> issues,
        int truncated,
        /*
         * Null until the outbox stamps it. Delivery is at-least-once — the POST can succeed and
         * the transaction marking it sent can fail — so the receiver needs a key to recognise the
         * repeat, and this is it. It lives here rather than only in the stored JSON because the
         * relay parses the payload back into this record before posting it: a field the record
         * does not declare is dropped on the way through, and the mapper is configured not to
         * complain about unknown properties, so it would be dropped in silence.
         */
        @JsonProperty("message_id") String messageId) {

    /**
     * How many issues are named in the body.
     *
     * <p>The rest are counted. A webhook body with four hundred entries is a denial of service
     * against its reader, and the API exists for the full list.
     */
    public static final int MAX_DETAILED_ISSUES = 10;

    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonPropertyOrder({"id", "identifier", "type", "severity", "is_kev", "epss_score", "package", "file_path", "fix_versions", "link"})
    public record Detail(
            long id,
            String identifier,
            String type,
            String severity,
            @JsonProperty("is_kev") boolean kev,
            @JsonProperty("epss_score") Double epssScore,
            @JsonProperty("package") String packageName,
            @JsonProperty("file_path") String filePath,
            /* The most useful field for whoever reads the alert. */
            @JsonProperty("fix_versions") String fixVersions,
            String link) {}

    /** An issue's contribution to the message. Deliberately narrower than the entity. */
    public record NotifiableIssue(
            long id,
            String identifier,
            FindingType type,
            Severity severity,
            boolean kev,
            Double epssScore,
            String packageName,
            String filePath,
            String fixVersions,
            String link) {

        Detail toDetail() {
            return new Detail(
                    id, identifier, type == null ? null : type.wireName(), severity == null ? null : severity.wireName(),
                    kev, epssScore, packageName, filePath, fixVersions, link);
        }
    }

    public record Delta(
            String targetName,
            long scanId,
            List<NotifiableIssue> newIssues,
            List<NotifiableIssue> reopenedIssues,
            int resolvedCount,
            Severity minSeverity) {}

    public static NotificationPayload of(Delta delta) {
        List<NotifiableIssue> all = new ArrayList<>(delta.newIssues());
        all.addAll(delta.reopenedIssues());

        long kevCount = all.stream().filter(NotifiableIssue::kev).count();

        List<String> parts = new ArrayList<>();
        if (!delta.newIssues().isEmpty()) {
            parts.add(delta.newIssues().size() + " new issue(s)");
        }
        if (!delta.reopenedIssues().isEmpty()) {
            parts.add(delta.reopenedIssues().size() + " reappeared");
        }
        if (kevCount > 0) {
            parts.add(kevCount + " actively exploited");
        }

        StringBuilder text = new StringBuilder("Vectispire — ")
                .append(delta.targetName())
                .append(": ")
                .append(String.join(", ", parts));
        if (delta.resolvedCount() > 0) {
            text.append(" (").append(delta.resolvedCount()).append(" resolved)");
        }

        return new NotificationPayload(
                text.toString(),
                delta.targetName(),
                delta.scanId(),
                delta.newIssues().size(),
                delta.reopenedIssues().size(),
                delta.resolvedCount(),
                kevCount,
                delta.minSeverity().wireName(),
                all.stream().limit(MAX_DETAILED_ISSUES).map(NotifiableIssue::toDetail).toList(),
                Math.max(0, all.size() - MAX_DETAILED_ISSUES),
                null);
    }
}
