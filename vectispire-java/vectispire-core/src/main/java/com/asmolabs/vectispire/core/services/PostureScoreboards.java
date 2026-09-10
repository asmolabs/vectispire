package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.TargetMaturityScore;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.TargetTotals;
import com.asmolabs.vectispire.core.repositories.IssueAggregates;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The all-time half of the posture dashboard, assembled from database aggregates.
 *
 * <p><b>Why this half cannot be windowed.</b> The scoreboard reports what a target carries and
 * what it has closed since it was added: a repository that fixed forty issues last year is
 * graded on that. Filtering it to the trend's window would change published grades, which is
 * exactly what the characterisation suite exists to catch — so the window narrows the curve and
 * leaves this alone.
 *
 * <p>What changes is where the counting happens. The open backlog is the larger half of an issue
 * table and it is now a {@code group by}; only the closed issues are read as rows, and only two
 * columns of them.
 *
 * <h2>One mapping that must not drift</h2>
 *
 * <p><b>A missing severity becomes {@code MEDIUM} here, and that is not this class's idea.</b>
 * The dashboard has always substituted it before the engine saw a row, so an unnamed severity
 * has always been penalised three points. The engine's own fallback for an unrecognised value is
 * {@code LOW}, worth one — so reading the column straight out of a {@code group by} and handing
 * it over would quietly lift every affected target's grade by two points per issue. The
 * substitution is repeated here to keep the number the same, not because it is the better rule.
 */
public final class PostureScoreboards {

    private PostureScoreboards() {}

    /** What the dashboard writes into a row with no severity, and has always written. */
    private static final String ASSUMED_SEVERITY = "MEDIUM";

    /**
     * @param openCounts one row per {@code (target, severity)} that still has unresolved issues
     * @param resolved one row per target: how many it has closed and how long they took
     * @param names resolved once by the caller, which already needs them for the curve
     */
    public static List<TargetMaturityScore> from(
            List<IssueAggregates.TargetSeverityCount> openCounts,
            List<IssueAggregates.TargetResolutions> resolved,
            TargetNaming.Names names) {

        // Insertion-ordered, so two targets on the same score come out in a stable order rather
        // than in whatever order a hash map happened to iterate. The engine's sort is stable, so
        // this is what decides ties — the previous implementation left them undefined.
        Map<String, Accumulator> byTarget = new LinkedHashMap<>();

        for (IssueAggregates.TargetSeverityCount row : openCounts) {
            accumulatorFor(byTarget, row.repoId(), row.containerId(), names)
                    .addOpen(row.severity() != null ? row.severity() : ASSUMED_SEVERITY, row.count());
        }

        for (IssueAggregates.TargetResolutions row : resolved) {
            // Seconds to days, and the engine's own rounding: the average now arrives from the
            // database, so this is the one line that has to keep producing the number the
            // characterisation suite pinned.
            accumulatorFor(byTarget, row.repoId(), row.containerId(), names)
                    .setResolved(
                            row.resolved(),
                            row.averageSeconds() == null
                                    ? null
                                    : PostureTrendAnalytics.roundDays(row.averageSeconds() / 86400.0));
        }

        return PostureTrendAnalytics.scoreboard(
                byTarget.values().stream().map(Accumulator::totals).toList());
    }

    private static Accumulator accumulatorFor(
            Map<String, Accumulator> byTarget, Long repoId, Long containerId, TargetNaming.Names names) {

        boolean isRepository = repoId != null;
        Long id = isRepository ? repoId : containerId;
        String kind = isRepository ? "REPOSITORY" : "CONTAINER";
        return byTarget.computeIfAbsent(
                kind + "-" + id, key -> new Accumulator(id, kind, names.of(repoId, containerId)));
    }

    private static final class Accumulator {

        private final Long id;
        private final String kind;
        private final String name;
        private long critical;
        private long high;
        private long medium;
        private long low;
        private long resolved;
        private Double meanDays;

        private Accumulator(Long id, String kind, String name) {
            this.id = id;
            this.kind = kind;
            this.name = name;
        }

        private void addOpen(String severity, long count) {
            if ("CRITICAL".equalsIgnoreCase(severity)) {
                critical += count;
            } else if ("HIGH".equalsIgnoreCase(severity)) {
                high += count;
            } else if ("MEDIUM".equalsIgnoreCase(severity)) {
                medium += count;
            } else {
                low += count;
            }
        }

        private void setResolved(long count, Double meanDays) {
            this.resolved = count;
            this.meanDays = meanDays;
        }

        private TargetTotals totals() {
            return new TargetTotals(id, kind, name, critical, high, medium, low, resolved, meanDays);
        }
    }
}
