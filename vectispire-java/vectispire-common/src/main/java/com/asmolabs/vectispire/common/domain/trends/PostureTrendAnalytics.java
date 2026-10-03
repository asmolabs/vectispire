package com.asmolabs.vectispire.common.domain.trends;

import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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

    /**
     * One target of the maturity ranking: <b>its scorecard's score and grade</b>, and the counts
     * beside them.
     *
     * <p>The score was a hundred less the open backlog, weighted by rules of this class's own and
     * saturating at zero — a target with fifty issues and one with five hundred both read 0, F —
     * while the card and the public badge of the same target showed another number and another
     * letter. It is now the card's, computed by the scorecard's service; this record only carries it.
     *
     * @param openCritical the counts the card grades on: open means neither closed nor resolved,
     *     settled triage left out, as on the card
     * @param totalResolved all time, like {@code targetMttrDays}; neither enters the score
     * @param securityScore 1 to 100; null exactly when {@code maturityGrade} is
     *     {@link SecurityGrade#NO_DATA} — the target holds no completed scan (decision 0007), and it
     *     ranks after every graded target
     * @param riskPoints the card's (decision 0036); null exactly when {@code securityScore} is. Two
     *     targets of one score — both at one deep in F, both at the exploited cap — rank by them, the
     *     fewer first
     */
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
            Integer securityScore,
            SecurityGrade maturityGrade,
            Double riskPoints) {}

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
     * The window's numbers from the issues that touch it, and a scoreboard computed elsewhere.
     *
     * @param windowIssues everything satisfying {@link #touchesWindow}. Passing more is harmless
     *     and passing less is not: an issue still open since last year belongs here, because it
     *     is in every day's backlog
     * @param scoreboard the maturity ranking, graded by the scorecard's service and ranked by its
     *     caller: all-time per-target figures, which no window can produce
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
     * One decimal place, the rounding every average of this class uses.
     *
     * <p>For a caller whose average was computed by the database: {@code avg(resolution_seconds)}
     * divided by a day is the same quantity, and it has to be rounded identically or a target's
     * figure disagrees in the first decimal with the window's about the same resolutions.
     */
    public static Double roundDays(double days) {
        return Math.round(days * 10.0) / 10.0;
    }

    private static Double average(List<Double> list) {
        if (list == null || list.isEmpty()) return null;
        double sum = 0.0;
        for (double val : list) sum += val;
        return roundDays(sum / list.size());
    }
}
