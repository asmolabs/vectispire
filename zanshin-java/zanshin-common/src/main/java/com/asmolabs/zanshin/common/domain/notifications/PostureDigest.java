package com.asmolabs.zanshin.common.domain.notifications;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The week's posture, for people who are not watching the dashboard.
 *
 * <h2>Why a periodic report exists at all</h2>
 *
 * <p>Every other notification here fires when something <b>appears</b>. That is the right trigger
 * for an alert and the wrong one for a report: on a quiet week nobody is told anything, and a quiet
 * week is also the week in which a target has silently not been scanned for twenty days, or a
 * backlog has been growing by four issues a day without any single one of them being newsworthy.
 * The absence of alerts reads as good news, and it is the one state that cannot be distinguished
 * from the scanners having stopped.
 *
 * <p>So this says how much there is, which way it is moving, and what was <b>not looked at</b> —
 * the last being the figure no alert can ever carry, because nothing happened.
 *
 * <h2>Direction is reported, never judged</h2>
 *
 * <p>{@code openedThisWeek} and {@code resolvedThisWeek} are given as they are, rather than
 * reduced to "improving" or "worsening". A week that resolved forty issues and opened forty-one is
 * not a bad week, and a label would say it was. The two numbers side by side let the reader draw
 * the conclusion they are accountable for.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PostureDigest(
        String text,
        @JsonProperty("week_of") String weekOf,
        @JsonProperty("open_total") long openTotal,
        @JsonProperty("backlog_by_severity") Map<String, Long> backlogBySeverity,
        @JsonProperty("opened_this_week") long openedThisWeek,
        @JsonProperty("resolved_this_week") long resolvedThisWeek,
        @JsonProperty("overdue_count") long overdueCount,
        @JsonProperty("failing_targets") int failingTargets,
        @JsonProperty("total_targets") int totalTargets,
        @JsonProperty("never_scanned") long neverScanned,
        @JsonProperty("last_scan_failed") long lastScanFailed,
        @JsonProperty("mean_days_to_resolve") Double meanDaysToResolve) {

    /**
     * The numbers a caller has to supply, kept apart from the rendering.
     *
     * <p>Its own record so that {@link #of} is a pure function of data the services already
     * compute — the gate's overview, the SLA count, the trend series — rather than a method that
     * reaches for six collaborators and cannot be tested without them.
     */
    public record Counts(
            long openTotal,
            Map<String, Long> backlogBySeverity,
            long openedThisWeek,
            long resolvedThisWeek,
            long overdueCount,
            int failingTargets,
            int totalTargets,
            long neverScanned,
            long lastScanFailed,
            Optional<Double> meanDaysToResolve) {}

    public static PostureDigest of(LocalDate weekStarting, Counts counts) {
        return new PostureDigest(
                summary(weekStarting, counts),
                weekStarting.toString(),
                counts.openTotal(),
                Map.copyOf(counts.backlogBySeverity() == null ? Map.of() : counts.backlogBySeverity()),
                counts.openedThisWeek(),
                counts.resolvedThisWeek(),
                counts.overdueCount(),
                counts.failingTargets(),
                counts.totalTargets(),
                counts.neverScanned(),
                counts.lastScanFailed(),
                counts.meanDaysToResolve().orElse(null));
    }

    /**
     * The one line a chat receiver that reads only {@code text} will show.
     *
     * <p>Ordered by what somebody has to act on, not by what is easiest to count: lateness first,
     * because it is the only figure with a deadline attached; then the direction; then what was
     * never examined, which is last in the sentence and first in consequence — an unscanned target
     * has an empty backlog and passes every policy.
     */
    private static String summary(LocalDate weekStarting, Counts counts) {
        StringBuilder text = new StringBuilder("Zanshin — week of ").append(weekStarting).append(": ")
                .append(counts.openTotal()).append(" open");
        if (counts.overdueCount() > 0) {
            text.append(", ").append(counts.overdueCount()).append(" past their remediation deadline");
        }
        text.append(". ")
                .append(counts.openedThisWeek()).append(" appeared, ")
                .append(counts.resolvedThisWeek()).append(" resolved. ")
                .append(counts.failingTargets()).append(" of ").append(counts.totalTargets())
                .append(" targets failing.");

        // **Named even when the number is zero would be silence.** A target nobody scanned and one
        // whose last scan failed both have an empty backlog, and an empty backlog passes every
        // policy — so a report that mentioned them only when convenient would let the most
        // dangerous state in the product read as the healthiest.
        if (counts.neverScanned() > 0 || counts.lastScanFailed() > 0) {
            text.append(" Not examined: ")
                    .append(counts.neverScanned()).append(" never scanned, ")
                    .append(counts.lastScanFailed()).append(" whose last scan failed.");
        }
        return text.toString();
    }

    /** The body of the e-mail, for a reader rather than a parser. */
    public String asPlainText() {
        StringBuilder body = new StringBuilder(text).append("\n\n");
        body.append("Open issues by severity\n");
        if (backlogBySeverity.isEmpty()) {
            body.append("  none\n");
        } else {
            // A stable order, so two consecutive weeks can be read side by side.
            new LinkedHashMap<>(backlogBySeverity)
                    .forEach((severity, count) -> body.append("  ").append(severity).append(": ").append(count)
                            .append('\n'));
        }
        body.append('\n');
        body.append("Appeared this week: ").append(openedThisWeek).append('\n');
        body.append("Resolved this week: ").append(resolvedThisWeek).append('\n');
        body.append("Past their deadline: ").append(overdueCount).append('\n');
        // Absent rather than "0 days": zero would read as "everything is fixed the day it appears",
        // which is the opposite of "nothing was resolved, so there is nothing to average".
        body.append("Mean days to resolve: ")
                .append(meanDaysToResolve == null
                        ? "no issue was resolved this week"
                        : String.format("%.1f", meanDaysToResolve))
                .append('\n');
        body.append('\n');
        body.append("Targets failing the gate: ").append(failingTargets).append(" of ").append(totalTargets)
                .append('\n');
        body.append("Never scanned: ").append(neverScanned).append('\n');
        body.append("Last scan failed: ").append(lastScanFailed).append('\n');
        return body.toString();
    }

    /** The subject line, which is what most recipients will actually read. */
    public String asSubject() {
        return "Zanshin — week of " + weekOf + ": " + openTotal + " open"
                + (overdueCount > 0 ? ", " + overdueCount + " late" : "");
    }
}
