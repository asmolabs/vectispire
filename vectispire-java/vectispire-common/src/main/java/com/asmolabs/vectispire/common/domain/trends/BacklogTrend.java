package com.asmolabs.zanshin.common.domain.trends;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The backlog over time, from the two dates every issue already carries.
 *
 * <h2>Why this is a calculation and not a query</h2>
 *
 * <p>Every engine spells date truncation differently — {@code date_trunc}, {@code DATE_FORMAT},
 * {@code strftime} — so a grouped query would be four queries, and the one that is wrong is wrong
 * on the engine nobody develops on. Here the database returns two timestamps per issue and the
 * buckets are counted in Java, which is portable by construction and testable without a server.
 *
 * <p>It is also the only shape in which the three series agree with each other. Counting "open on
 * day D" with one query, "opened on day D" with a second and "resolved" with a third gives three
 * definitions of a day boundary, and they part company at the first timezone question.
 *
 * <h2>The conventions, because each one is a choice somebody would make differently</h2>
 *
 * <p><b>A bucket is a calendar day in UTC.</b> Not the server's zone: two instances in two zones
 * must draw the same chart, and a reader comparing a screenshot to a report should not have to ask
 * where each was rendered. The same reasoning as the canonical instant the audit chain hashes.
 *
 * <p><b>"Open" means open at the <em>end</em> of the day.</b> An issue first seen at 23:00 counts
 * on that day, and one resolved at 01:00 does not. Stated because "open on day D" has three
 * defensible readings, and a chart whose steps land a day away from the events that caused them is
 * a chart people stop trusting without being able to say why.
 *
 * <p><b>The mean time to resolve covers what was resolved <em>in the window</em>.</b> Averaged over
 * everything ever resolved, the figure barely moves and therefore says nothing about whether the
 * team is getting faster — which is the only question anybody asks it.
 */
public final class BacklogTrend {

    private BacklogTrend() {}

    /**
     * One issue's life, as the two columns it already has.
     *
     * @param resolvedAt {@code null} while the issue is open. Not an epoch sentinel: a resolved
     *     date in 1970 would silently count as resolved before it was seen
     */
    public record Lifespan(Instant firstSeen, Instant resolvedAt) {}

    /**
     * @param open how many issues stood open at the end of this day
     * @param opened how many were first seen during it
     * @param resolved how many were resolved during it
     */
    public record Point(LocalDate day, long open, long opened, long resolved) {}

    /**
     * @param meanDaysToResolve empty when nothing was resolved in the window — <b>not zero</b>.
     *     Zero reads as "everything is fixed the day it appears", which is the opposite of "we have
     *     no measurement", and it is the same distinction {@code ScanArtifacts} draws between an
     *     absent step and an empty result
     * @param resolvedInWindow the population the mean was taken over, so a reader can see whether
     *     it rests on three issues or three hundred
     */
    public record Series(List<Point> points, Optional<Double> meanDaysToResolve, int resolvedInWindow) {}

    /**
     * The three series, day by day, over an inclusive window.
     *
     * @param lifespans every issue that could have been open during the window. A caller that
     *     filters them by visibility hands in fewer; that filtering is not this function's business
     *     and must not be, or there would be two places deciding who sees what
     */
    public static Series over(List<Lifespan> lifespans, LocalDate from, LocalDate to) {
        if (from.isAfter(to)) {
            throw new IllegalArgumentException("The window ends before it starts: " + from + " to " + to);
        }

        List<Point> points = new ArrayList<>();
        for (LocalDate day = from; !day.isAfter(to); day = day.plusDays(1)) {
            Instant endOfDay = day.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
            Instant startOfDay = day.atStartOfDay(ZoneOffset.UTC).toInstant();

            long open = 0;
            long opened = 0;
            long resolved = 0;
            for (Lifespan issue : lifespans) {
                if (issue.firstSeen() == null) {
                    // A row with no first sighting cannot be placed on the axis. Skipped rather
                    // than dated today, which would draw a spike on whichever day the chart was
                    // opened.
                    continue;
                }
                if (within(issue.firstSeen(), startOfDay, endOfDay)) {
                    opened++;
                }
                if (issue.resolvedAt() != null && within(issue.resolvedAt(), startOfDay, endOfDay)) {
                    resolved++;
                }
                boolean seenByNow = issue.firstSeen().isBefore(endOfDay);
                boolean stillOpen = issue.resolvedAt() == null || !issue.resolvedAt().isBefore(endOfDay);
                if (seenByNow && stillOpen) {
                    open++;
                }
            }
            points.add(new Point(day, open, opened, resolved));
        }

        return new Series(List.copyOf(points), meanDaysToResolve(lifespans, from, to), resolvedIn(lifespans, from, to));
    }

    private static boolean within(Instant moment, Instant startInclusive, Instant endExclusive) {
        return !moment.isBefore(startInclusive) && moment.isBefore(endExclusive);
    }

    private static Optional<Double> meanDaysToResolve(List<Lifespan> lifespans, LocalDate from, LocalDate to) {
        Instant start = from.atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant end = to.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();

        long count = 0;
        double totalDays = 0;
        for (Lifespan issue : lifespans) {
            if (issue.resolvedAt() == null || issue.firstSeen() == null) {
                continue;
            }
            if (!within(issue.resolvedAt(), start, end)) {
                continue;
            }
            // **Clamped at zero rather than left negative.** A resolution timestamp before the
            // first sighting is bad data — a clock stepping back, a row written by hand — and one
            // such issue with a negative age would pull the mean below anything real and be read
            // as an improvement.
            long seconds = Math.max(0, Duration.between(issue.firstSeen(), issue.resolvedAt()).toSeconds());
            totalDays += seconds / (double) Duration.ofDays(1).toSeconds();
            count++;
        }

        return count == 0 ? Optional.empty() : Optional.of(totalDays / count);
    }

    private static int resolvedIn(List<Lifespan> lifespans, LocalDate from, LocalDate to) {
        Instant start = from.atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant end = to.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
        int count = 0;
        for (Lifespan issue : lifespans) {
            if (issue.resolvedAt() != null && issue.firstSeen() != null && within(issue.resolvedAt(), start, end)) {
                count++;
            }
        }
        return count;
    }
}
