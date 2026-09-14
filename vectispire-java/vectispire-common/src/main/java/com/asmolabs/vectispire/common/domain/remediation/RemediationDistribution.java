package com.asmolabs.vectispire.common.domain.remediation;

import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * How long remediation actually takes, as a shape rather than as an average.
 *
 * <h2>Why an average is the wrong instrument</h2>
 *
 * <p><b>A mean is dragged by the volume of easy fixes.</b> An estate that closes two hundred low
 * findings in a day and leaves one critical open for eight months reports a mean of a day or two,
 * and that number is true and says nothing. What a process obligation asks is different: what
 * fraction was fixed inside its window, and how bad is the worst thing still open.
 *
 * <p>So this reports three things per severity and no average at all: the share resolved inside
 * the deadline, the median and the ninetieth percentile, and the age of the oldest item still
 * open. The last one is the figure a mean can never show and the one an assessor asks for first.
 *
 * <h2>The window, and what it is for</h2>
 *
 * <p>Resolutions are counted over a window rather than over all history, because a process
 * indicator answers "how are we doing lately" and not "how have we ever done". A team that fixed
 * its habits three months ago deserves a number that says so, and an all-time mean would hide it
 * for years.
 *
 * <p><b>Open items are not windowed</b>, and cannot be: an issue open for eight months is the
 * point of the measurement, and a ninety-day window would be exactly the filter that hides it.
 */
public record RemediationDistribution(
        int windowDays, List<BySeverity> bySeverity, Long oldestOpenDays, Severity oldestOpenSeverity) {

    public RemediationDistribution {
        bySeverity = List.copyOf(bySeverity);
    }

    /**
     * One severity's shape.
     *
     * @param windowDays the deadline for this severity, or zero when none is set — a percentage
     *     "within SLA" against no SLA would be a hundred per cent by construction, so it is null
     *     rather than flattering
     * @param withinSla resolutions that beat the deadline
     * @param late resolutions that did not. Kept beside {@code withinSla} rather than as a
     *     percentage alone: two out of three and two hundred out of three hundred are the same
     *     ratio and not the same fact
     * @param medianDays the middle resolution, which is what a typical fix costs
     * @param ninetiethDays the tail. <b>This is the number that moves when a process is
     *     failing</b>, while the median stays reassuring
     * @param openOverdue items still open past their deadline right now
     * @param oldestOpenDays the age of the oldest open item at this severity
     */
    public record BySeverity(
            Severity severity,
            int windowDays,
            long withinSla,
            long late,
            Double percentageWithinSla,
            Double medianDays,
            Double ninetiethDays,
            long openOverdue,
            Long oldestOpenDays) {}

    /** One resolved issue, as the store hands it over: a severity and a measured duration. */
    public record Resolved(Severity severity, long seconds) {}

    /** One severity's open backlog, already aggregated by the database. */
    public record Open(Severity severity, long total, long overdue, Long oldestDays) {}

    private static final double SECONDS_PER_DAY = 86_400.0;

    public static RemediationDistribution calculate(
            int windowDays, RemediationSla sla, List<Resolved> resolved, List<Open> open) {

        Map<Severity, List<Long>> secondsBySeverity = new EnumMap<>(Severity.class);
        for (Resolved item : resolved) {
            if (item.severity() != null) {
                secondsBySeverity
                        .computeIfAbsent(item.severity(), key -> new ArrayList<>())
                        .add(item.seconds());
            }
        }

        Map<Severity, Open> openBySeverity = new EnumMap<>(Severity.class);
        open.forEach(row -> {
            if (row.severity() != null) {
                openBySeverity.put(row.severity(), row);
            }
        });

        List<BySeverity> rows = new ArrayList<>();
        for (Severity severity : Severity.values()) {
            List<Long> seconds = secondsBySeverity.getOrDefault(severity, List.of());
            Open backlog = openBySeverity.get(severity);
            long deadlineSeconds = sla.windowFor(severity).map(Duration::toSeconds).orElse(0L);

            long within = 0;
            long late = 0;
            for (long value : seconds) {
                if (deadlineSeconds > 0 && value > deadlineSeconds) {
                    late++;
                } else {
                    within++;
                }
            }

            rows.add(new BySeverity(
                    severity,
                    (int) (deadlineSeconds / 86_400),
                    within,
                    late,
                    // No deadline means no percentage: reporting 100% against a window nobody set
                    // would be a claim earned by an absent rule.
                    deadlineSeconds == 0 || seconds.isEmpty() ? null : round((100.0 * within) / seconds.size()),
                    percentile(seconds, 50),
                    percentile(seconds, 90),
                    backlog == null ? 0 : backlog.overdue(),
                    backlog == null ? null : backlog.oldestDays()));
        }

        Open worst = open.stream()
                .filter(row -> row.oldestDays() != null)
                .max(Comparator.comparingLong(Open::oldestDays))
                .orElse(null);

        return new RemediationDistribution(
                windowDays,
                rows,
                worst == null ? null : worst.oldestDays(),
                worst == null ? null : worst.severity());
    }

    /**
     * The nearest-rank percentile, computed on a copy.
     *
     * <p>Nearest-rank rather than an interpolating definition: with four resolutions there is no
     * meaningful point between two of them, and a number invented by interpolation would be a
     * duration nobody's issue ever had.
     */
    private static Double percentile(List<Long> seconds, int percentile) {
        if (seconds.isEmpty()) {
            return null;
        }
        List<Long> sorted = new ArrayList<>(seconds);
        sorted.sort(Comparator.naturalOrder());
        int rank = (int) Math.ceil((percentile / 100.0) * sorted.size());
        return round(sorted.get(Math.clamp(rank - 1, 0, sorted.size() - 1)) / SECONDS_PER_DAY);
    }

    private static double round(double value) {
        return Math.round(value * 10.0) / 10.0;
    }
}
