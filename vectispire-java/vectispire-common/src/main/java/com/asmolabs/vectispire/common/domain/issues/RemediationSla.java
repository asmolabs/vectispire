package com.asmolabs.vectispire.common.domain.issues;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

/**
 * How long a finding of a given severity may stay open.
 *
 * <p><b>What this adds to a backlog that already sorts by severity.</b> A {@code critical} opened
 * yesterday and one opened nine months ago are the same row today, distinguished only by a date
 * nobody compares against anything. A remediation window turns that date into a verdict —
 * <em>late</em> — which is the figure a security officer is asked for and the one no scanner
 * produces.
 *
 * <p><b>It blocks nothing.</b> No SLA enters a gate verdict, for the reason
 * {@code 0005-quality-never-blocks-the-gate} gives about quality: a gate that starts failing
 * builds the day a policy is switched on is a gate that gets switched off by lunchtime. Being
 * late is a fact to report to people, not a reason to stop a deployment that carries the fix.
 *
 * <h2>The four decisions in here</h2>
 *
 * <ol>
 *   <li><b>The clock starts at {@code firstSeenAt}, never at the last scan.</b> An issue found
 *       again this morning is not new. Restarting from the last sighting would make the deadline
 *       unreachable by construction: a target scanned nightly would reset every window every
 *       night, and nothing would ever be late.
 *   <li><b>A settled issue has no deadline.</b> Fixed, or argued not to apply — a human decision
 *       took it out of the way, and counting it as late would punish the triage this system
 *       exists to encourage. An accepted risk that <em>should</em> come back is a different
 *       feature: an exception with an expiry, not an SLA quietly ignoring the decision.
 *   <li><b>A window of zero means "no deadline at this severity", not "due immediately".</b>
 *       Read the other way, an operator clearing a field would put every {@code low} in the
 *       backlog into breach at once — the reading that produces an alarm nobody can act on, from
 *       a gesture that looked like turning something off.
 *   <li><b>Due-soon is a fixed week, not a fraction of the window.</b> A quarter of a 180-day
 *       window is 45 days of "due soon", which teaches people that the badge means nothing. A
 *       week is the horizon teams actually schedule in.
 * </ol>
 */
public record RemediationSla(Map<Severity, Duration> windows) {

    /** Past this, "due soon". See the note above on why it is not proportional. */
    public static final Duration DUE_SOON = Duration.ofDays(7);

    /**
     * A starting point, not a standard.
     *
     * <p>15 / 30 / 90 / 180 days is the shape most published policies have — tighter for what is
     * exploitable now, generous for what is theoretical. Every deployment overrides it, which is
     * why these are settings; what matters is that the defaults are <em>not</em> zero, because a
     * feature that ships switched off is a feature nobody discovers.
     *
     * <p>{@code NEGLIGIBLE} and {@code UNKNOWN} carry no window. Neither describes work anybody
     * schedules: the first is judged not to matter, and the second is what a scanner says when it
     * does not know — putting a deadline on either would fill the report with lateness that means
     * nothing.
     */
    public static final RemediationSla DEFAULT = new RemediationSla(Map.of(
            Severity.CRITICAL, Duration.ofDays(15),
            Severity.HIGH, Duration.ofDays(30),
            Severity.MEDIUM, Duration.ofDays(90),
            Severity.LOW, Duration.ofDays(180)));

    public RemediationSla {
        Map<Severity, Duration> copy = new EnumMap<>(Severity.class);
        windows.forEach((severity, window) -> {
            // Zero and negative are both "no deadline". A negative window can only come from a
            // stored value nobody validated, and the safe reading of it is the one that raises no
            // alarm rather than the one that puts a whole backlog in breach.
            if (severity != null && window != null && !window.isZero() && !window.isNegative()) {
                copy.put(severity, window);
            }
        });
        windows = Map.copyOf(copy);
    }

    /** Where an issue stands against its window. */
    public enum SlaState {

        /** Inside the window, with more than {@link #DUE_SOON} to go. */
        ON_TIME,

        /** Inside the window, and due within a week. */
        DUE_SOON,

        /** Past its window. The only state worth a figure on a report. */
        OVERDUE
    }

    /**
     * @param dueAt when the window closes — an instant, so the client formats it in the reader's
     *     zone rather than in the server's
     * @param state where it stands
     * @param days days until due, <b>negative when late</b>. One signed field rather than two,
     *     because "3 days late" and "due in 12 days" are the same measurement read from opposite
     *     sides, and two fields would allow a row that is both
     */
    public record Assessment(Instant dueAt, SlaState state, long days) {

        public boolean isOverdue() {
            return state == SlaState.OVERDUE;
        }
    }

    /**
     * The window for a severity, or empty when that severity has none.
     *
     * <p>{@code Optional} rather than {@code Duration.ZERO}: "no deadline" and "a deadline of
     * zero" are different answers, and only one of them is representable as a duration.
     */
    public Optional<Duration> windowFor(Severity severity) {
        return Optional.ofNullable(windows.get(severity));
    }

    /**
     * Where one issue stands, or empty when no deadline applies to it.
     *
     * @param open whether the issue is still open. A resolved issue has no deadline: it is done,
     *     and reporting it as late would describe work that has already happened
     * @param settled whether a triage decision has taken it out of the way — see the class note
     */
    public Optional<Assessment> assess(
            Severity severity, Instant firstSeenAt, boolean open, boolean settled, Instant now) {

        if (!open || settled || firstSeenAt == null || now == null) {
            return Optional.empty();
        }

        return windowFor(severity).map(window -> {
            Instant dueAt = firstSeenAt.plus(window);
            // **Lateness is decided by the instant, the day count is only for display.** Deriving
            // it from the count would call an issue due in twenty-three hours "0 days" and then
            // have to decide whether zero is late; comparing instants has one answer.
            boolean late = now.isAfter(dueAt);
            long days = ChronoUnit.DAYS.between(now, dueAt);

            SlaState state;
            if (late) {
                state = SlaState.OVERDUE;
            } else if (!dueAt.minus(DUE_SOON).isAfter(now)) {
                state = SlaState.DUE_SOON;
            } else {
                state = SlaState.ON_TIME;
            }
            return new Assessment(dueAt, state, days);
        });
    }

    /**
     * The instant before which an issue of this severity is late.
     *
     * <p>For asking the database rather than memory: lateness is {@code first_seen_at < now -
     * window}, one indexed comparison, where evaluating {@link #assess} per row would mean
     * reading the whole backlog to produce one number.
     */
    public Optional<Instant> overdueBefore(Severity severity, Instant now) {
        return windowFor(severity).map(now::minus);
    }

    /**
     * Every threshold at once, for the severities that have a window.
     *
     * <p><b>Why the whole map rather than one call per severity.</b> "Overdue" is not one
     * comparison but a union of them — a critical older than fifteen days <em>or</em> a high
     * older than thirty — so a query built from this map answers in one pass what four queries
     * would answer in four. It is also the same object the list filter and the count both use,
     * which is what keeps the figure and the rows behind it in agreement.
     */
    public Map<Severity, Instant> overdueThresholds(Instant now) {
        Map<Severity, Instant> thresholds = new EnumMap<>(Severity.class);
        windows.forEach((severity, window) -> thresholds.put(severity, now.minus(window)));
        return Map.copyOf(thresholds);
    }
}
