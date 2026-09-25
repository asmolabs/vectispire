package com.asmolabs.vectispire.common.domain.trends;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Enterprise security posture analytics, multi-echelon MTTR trends,
 * resolution velocity (burn-down), and target maturity ranking.
 */
public record PostureTrendAnalytics(
        int windowDays,
        Double overallMttrDays,
        Map<String, Double> mttrBySeverity,
        long totalOpenedInWindow,
        long totalResolvedInWindow,
        double netResolutionRatePercentage, // (resolved / (opened + 1)) * 100
        List<DailyPosturePoint> dailySeries,
        List<TargetMaturityScore> targetScoreboard) {

    public record IssueObservation(
            Long targetId,
            String targetKind,
            String targetName,
            String severity, // CRITICAL, HIGH, MEDIUM, LOW
            Instant firstSeen,
            Instant resolvedAt) {}

    public record DailyPosturePoint(
            LocalDate date,
            long openBacklog,
            long newlyDiscovered,
            long newlyResolved,
            Double rollingMttrDays) {}

    public record TargetMaturityScore(
            Long targetId,
            String targetKind,
            String targetName,
            long openCritical,
            long openHigh,
            long openMedium,
            long openLow,
            long totalResolved,
            Double targetMttrDays,
            int securityScore, // 0 - 100
            String maturityGrade) {} // A, B, C, D, F

    /**
     * The instant the window opens. Public because a caller filtering in SQL has to compute the
     * same boundary, and two implementations of "ten days ago" is one too many.
     */
    public static Instant windowStart(int windowDays, Instant now) {
        return now.minus(Duration.ofDays(windowDays));
    }

    /**
     * Whether an observation can affect anything but the scoreboard.
     *
     * <p><b>This predicate is the whole refactoring.</b> An issue resolved before the window
     * opened contributes nothing to the daily series — for every day in the window its
     * resolution is already past, so it is never in the backlog, never newly discovered and
     * never newly resolved — and nothing to the window's own totals, which all require an
     * instant at or after the start. It contributes only to the target scoreboard, which is
     * all-time by design. So the series can be computed from a small set and the scoreboard from
     * aggregates, instead of both from every issue in the estate.
     *
     * <p>The third clause looks redundant and is not. An issue whose {@code resolvedAt} precedes
     * its {@code firstSeen} — impossible in principle, present in real data — would otherwise be
     * dropped here while the unfiltered engine still counts it as opened in the window. Keeping
     * it costs nothing and makes the two paths agree on inputs nobody meant to create.
     *
     * <p>A caller filtering in SQL writes exactly this: {@code resolved_at is null or resolved_at
     * >= :windowStart or first_seen_at >= :windowStart}.
     */
    public static boolean touchesWindow(IssueObservation obs, Instant windowStart) {
        return obs.resolvedAt() == null
                || !obs.resolvedAt().isBefore(windowStart)
                || (obs.firstSeen() != null && !obs.firstSeen().isBefore(windowStart));
    }

    /**
     * The whole estate in memory, which is what a caller holding every issue already has.
     *
     * <p>Kept so that the characterisation suite goes on measuring the arithmetic rather than
     * the plumbing: it feeds this, the dashboard feeds the four-argument form below, and a
     * divergence between them is a test failure rather than a wrong number on a screen.
     */
    public static PostureTrendAnalytics calculate(
            int windowDays,
            Instant now,
            List<IssueObservation> issues) {

        Instant start = windowStart(windowDays, now);
        return calculate(
                windowDays,
                now,
                issues.stream().filter(obs -> touchesWindow(obs, start)).toList(),
                scoreboardOf(issues));
    }

    /**
     * The window's numbers from the issues that touch it, and a scoreboard computed elsewhere.
     *
     * @param windowIssues everything satisfying {@link #touchesWindow}. Passing more is harmless
     *     and passing less is not: an issue still open since last year belongs here, because it
     *     is in every day's backlog
     * @param scoreboard all-time per-target totals, which no window can produce — see
     *     {@link #score(TargetTotals)}
     */
    public static PostureTrendAnalytics calculate(
            int windowDays,
            Instant now,
            List<IssueObservation> windowIssues,
            List<TargetMaturityScore> scoreboard) {

        List<IssueObservation> issues = windowIssues;
        Instant windowStart = windowStart(windowDays, now);
        LocalDate startDate = windowStart.atZone(ZoneOffset.UTC).toLocalDate();
        LocalDate endDate = now.atZone(ZoneOffset.UTC).toLocalDate();

        Map<String, List<Double>> resolvedDurationsBySev = new HashMap<>();
        List<Double> allResolvedDurations = new ArrayList<>();

        long totalOpened = 0;
        long totalResolved = 0;

        for (IssueObservation obs : issues) {
            if (obs.resolvedAt() != null
                    && obs.firstSeen() != null
                    && obs.resolvedAt().isAfter(obs.firstSeen())
                    && !obs.resolvedAt().isBefore(windowStart)) {

                double days = Duration.between(obs.firstSeen(), obs.resolvedAt()).toSeconds() / 86400.0;
                totalResolved++;
                allResolvedDurations.add(days);
                resolvedDurationsBySev
                        .computeIfAbsent(
                                obs.severity() != null ? obs.severity().toUpperCase(Locale.ROOT) : "UNKNOWN",
                                k -> new ArrayList<>())
                        .add(days);
            }

            if (obs.firstSeen() != null && !obs.firstSeen().isBefore(windowStart)) {
                totalOpened++;
            }
        }

        Double overallMttr = average(allResolvedDurations);
        Map<String, Double> mttrBySev = new HashMap<>();
        for (Map.Entry<String, List<Double>> e : resolvedDurationsBySev.entrySet()) {
            mttrBySev.put(e.getKey(), average(e.getValue()));
        }

        double velocityRate = totalOpened > 0 ? ((double) totalResolved / totalOpened) * 100.0 : (totalResolved > 0 ? 100.0 : 0.0);

        // Compute daily series
        List<DailyPosturePoint> dailyPoints = new ArrayList<>();
        LocalDate cur = startDate;
        while (!cur.isAfter(endDate)) {
            Instant dayStart = cur.atStartOfDay(ZoneOffset.UTC).toInstant();
            Instant dayEnd = cur.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();

            long openCount = 0;
            long openedDay = 0;
            long resolvedDay = 0;
            List<Double> dayDurations = new ArrayList<>();

            for (IssueObservation obs : issues) {
                boolean seenBeforeEnd = obs.firstSeen() != null && obs.firstSeen().isBefore(dayEnd);
                boolean resolvedAfterEnd = obs.resolvedAt() == null || obs.resolvedAt().isAfter(dayEnd);

                if (seenBeforeEnd && resolvedAfterEnd) {
                    openCount++;
                }

                if (obs.firstSeen() != null && !obs.firstSeen().isBefore(dayStart) && obs.firstSeen().isBefore(dayEnd)) {
                    openedDay++;
                }

                if (obs.resolvedAt() != null && !obs.resolvedAt().isBefore(dayStart) && obs.resolvedAt().isBefore(dayEnd)) {
                    resolvedDay++;
                    if (obs.firstSeen() != null) {
                        dayDurations.add(Duration.between(obs.firstSeen(), obs.resolvedAt()).toSeconds() / 86400.0);
                    }
                }
            }

            dailyPoints.add(new DailyPosturePoint(cur, openCount, openedDay, resolvedDay, average(dayDurations)));
            cur = cur.plusDays(1);
        }

        return new PostureTrendAnalytics(
                windowDays,
                overallMttr,
                mttrBySev,
                totalOpened,
                totalResolved,
                Math.round(velocityRate * 10.0) / 10.0,
                dailyPoints,
                scoreboard);
    }

    /**
     * What a target contributes to the scoreboard, and all of it is all-time.
     *
     * <p><b>The shape a database can produce.</b> The four open counts and the resolved count
     * are {@code group by} and nothing else, so they never leave the engine as rows. The average
     * resolution time is the one field that is not: it needs the difference between two
     * timestamps, and no query in this codebase does date arithmetic — the three dialects spell
     * it three ways and only one of them can be tested without a daemon. So it stays a number
     * the caller computes, and {@link #averageDays} is what it must use to get the same rounding.
     *
     * <p>The durable answer is to write the resolution's length beside the resolution, at the
     * moment it happens: an {@code avg} over a plain number is portable, and the migration that
     * adds the column is the honest place for that decision.
     *
     * @param mttrDays null when the target has resolved nothing that lived measurably
     */
    public record TargetTotals(
            Long targetId,
            String targetKind,
            String targetName,
            long openCritical,
            long openHigh,
            long openMedium,
            long openLow,
            long totalResolved,
            Double mttrDays) {}

    /**
     * The penalty, the score and the grade — the part that is a rule rather than a count.
     *
     * <p>An open critical costs twenty-five points, a high ten, a medium three and anything else
     * one. <b>Anything else, including a severity nobody recognises</b>: an unknown value is
     * scored as low rather than reported as unknown, which is the behaviour as it stands and is
     * pinned by the characterisation suite.
     */
    public static TargetMaturityScore score(TargetTotals totals) {
        int penalty = (int) (totals.openCritical() * 25
                + totals.openHigh() * 10
                + totals.openMedium() * 3
                + totals.openLow());
        int score = Math.max(0, Math.min(100, 100 - penalty));
        String grade = score >= 90 ? "A" : (score >= 75 ? "B" : (score >= 50 ? "C" : (score >= 30 ? "D" : "F")));

        return new TargetMaturityScore(
                totals.targetId(),
                totals.targetKind(),
                totals.targetName() != null ? totals.targetName() : "target-" + totals.targetId(),
                totals.openCritical(),
                totals.openHigh(),
                totals.openMedium(),
                totals.openLow(),
                totals.totalResolved(),
                totals.mttrDays(),
                score,
                grade);
    }

    /** Best score first. Ties keep the order they arrived in, which is the caller's to decide. */
    public static List<TargetMaturityScore> scoreboard(List<TargetTotals> totals) {
        List<TargetMaturityScore> scores = new ArrayList<>(totals.stream()
                .map(PostureTrendAnalytics::score)
                .toList());
        scores.sort((a, b) -> Integer.compare(b.securityScore(), a.securityScore()));
        return scores;
    }

    /**
     * The rounding the scoreboard has always used, exposed so a caller averaging elsewhere
     * produces the same number rather than one that differs in the first decimal.
     */
    public static Double averageDays(List<Double> days) {
        return average(days);
    }

    /**
     * One decimal place, the same way {@link #averageDays} gets there.
     *
     * <p>For a caller whose average was computed by the database: {@code avg(resolution_seconds)}
     * divided by a day is the same quantity, and it has to be rounded identically or a scoreboard
     * read from aggregates disagrees in the first decimal with one read from rows.
     */
    public static Double roundDays(double days) {
        return Math.round(days * 10.0) / 10.0;
    }

    /** The scoreboard from raw observations — the in-memory path, and what the aggregates replace. */
    private static List<TargetMaturityScore> scoreboardOf(List<IssueObservation> issues) {
        Map<String, TargetAggregator> aggregators = new HashMap<>();
        for (IssueObservation obs : issues) {
            TargetAggregator agg = aggregators.computeIfAbsent(
                    obs.targetKind() + "-" + obs.targetId(),
                    key -> new TargetAggregator(obs.targetId(), obs.targetKind(), obs.targetName()));

            if (obs.resolvedAt() == null) {
                agg.incrementOpen(obs.severity());
            } else {
                agg.incrementResolved();
                if (obs.firstSeen() != null && obs.resolvedAt().isAfter(obs.firstSeen())) {
                    agg.addDuration(Duration.between(obs.firstSeen(), obs.resolvedAt()).toSeconds() / 86400.0);
                }
            }
        }

        return scoreboard(aggregators.values().stream()
                .map(TargetAggregator::totals)
                .toList());
    }

    private static Double average(List<Double> list) {
        if (list == null || list.isEmpty()) return null;
        double sum = 0.0;
        for (double val : list) sum += val;
        return roundDays(sum / list.size());
    }

    private static final class TargetAggregator {
        private final Long id;
        private final String kind;
        private final String name;
        private long critical = 0;
        private long high = 0;
        private long medium = 0;
        private long low = 0;
        private long resolved = 0;
        private final List<Double> durations = new ArrayList<>();

        TargetAggregator(Long id, String kind, String name) {
            this.id = id;
            this.kind = kind;
            this.name = name != null ? name : "target-" + id;
        }

        void incrementOpen(String severity) {
            if ("CRITICAL".equalsIgnoreCase(severity)) critical++;
            else if ("HIGH".equalsIgnoreCase(severity)) high++;
            else if ("MEDIUM".equalsIgnoreCase(severity)) medium++;
            else low++;
        }

        void incrementResolved() {
            resolved++;
        }

        void addDuration(double days) {
            durations.add(days);
        }

        TargetTotals totals() {
            return new TargetTotals(id, kind, name, critical, high, medium, low, resolved, average(durations));
        }
    }
}
