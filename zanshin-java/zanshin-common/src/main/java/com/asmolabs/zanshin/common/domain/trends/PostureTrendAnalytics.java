package com.asmolabs.zanshin.common.domain.trends;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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

    public static PostureTrendAnalytics calculate(
            int windowDays,
            Instant now,
            List<IssueObservation> issues) {

        Instant windowStart = now.minus(Duration.ofDays(windowDays));
        LocalDate startDate = windowStart.atZone(ZoneOffset.UTC).toLocalDate();
        LocalDate endDate = now.atZone(ZoneOffset.UTC).toLocalDate();

        Map<String, List<Double>> resolvedDurationsBySev = new HashMap<>();
        List<Double> allResolvedDurations = new ArrayList<>();

        long totalOpened = 0;
        long totalResolved = 0;

        Map<String, TargetAggregator> targetAggregators = new HashMap<>();

        for (IssueObservation obs : issues) {
            String targetKey = obs.targetKind() + "-" + obs.targetId();
            TargetAggregator agg = targetAggregators.computeIfAbsent(
                    targetKey,
                    k -> new TargetAggregator(obs.targetId(), obs.targetKind(), obs.targetName()));

            boolean isOpen = obs.resolvedAt() == null;
            if (isOpen) {
                agg.incrementOpen(obs.severity());
            } else {
                agg.incrementResolved();
                if (obs.firstSeen() != null && obs.resolvedAt().isAfter(obs.firstSeen())) {
                    double days = Duration.between(obs.firstSeen(), obs.resolvedAt()).toSeconds() / 86400.0;
                    agg.addDuration(days);

                    if (!obs.resolvedAt().isBefore(windowStart)) {
                        totalResolved++;
                        allResolvedDurations.add(days);
                        resolvedDurationsBySev
                                .computeIfAbsent(obs.severity() != null ? obs.severity().toUpperCase() : "UNKNOWN", k -> new ArrayList<>())
                                .add(days);
                    }
                }
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

        // Compute Target maturity scores
        List<TargetMaturityScore> scoreboard = new ArrayList<>();
        for (TargetAggregator agg : targetAggregators.values()) {
            scoreboard.add(agg.buildScore());
        }
        scoreboard.sort((a, b) -> Integer.compare(b.securityScore(), a.securityScore()));

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

    private static Double average(List<Double> list) {
        if (list == null || list.isEmpty()) return null;
        double sum = 0.0;
        for (double val : list) sum += val;
        return Math.round((sum / list.size()) * 10.0) / 10.0;
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

        TargetMaturityScore buildScore() {
            int penalty = (int) (critical * 25 + high * 10 + medium * 3 + low * 1);
            int score = Math.max(0, Math.min(100, 100 - penalty));

            String grade = score >= 90 ? "A" : (score >= 75 ? "B" : (score >= 50 ? "C" : (score >= 30 ? "D" : "F")));
            return new TargetMaturityScore(id, kind, name, critical, high, medium, low, resolved, average(durations), score, grade);
        }
    }
}
