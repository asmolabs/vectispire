package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.dependencies.Versions;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.notifications.PostureDigest;
import com.asmolabs.vectispire.common.domain.remediation.RemediationCoverage;
import com.asmolabs.vectispire.common.domain.remediation.RemediationDistribution;
import com.asmolabs.vectispire.common.domain.scorecard.CandidateScore;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SvgBadgeGenerator;
import com.asmolabs.vectispire.common.domain.trends.BacklogTrend;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.vectispire.core.RustReference;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The decisions of the posture module the Rust port ({@code cp-posture}) is held to, written to
 * {@code vectispire-rust/reference/posture/decisions.json} before that port: the grade a score reads, the
 * formula of decision 0036 over a grid of backlogs and weights and the weights it refuses, the coverage cap,
 * the badge's SVG, the backlog's daily series, the posture analytics, the remediation distribution and
 * coverage, the version a fix recommends, and the weekly report's text.
 *
 * <p>Pure functions over chosen inputs, because what reaches the wire through the routes is replayed from the
 * recorded traffic: this set is for the arithmetic the recordings exercise only at a few points — a rounding at a
 * boundary, a cap at the exploited ceiling — and for the report, which no route serves.
 */
class PostureReferenceSetTest {

    @Test
    void theAnswersTheRustPortIsHeldTo() {
        ObjectNode out = RustReference.object();
        out.set("grades", grades());
        out.set("gradeLabels", gradeLabels());
        out.set("candidateScores", candidateScores());
        out.set("refusedWeights", refusedWeights());
        out.set("coverageCap", coverageCap());
        out.set("badges", badges());
        out.set("backlogTrend", backlogTrend());
        out.set("postureTrend", postureTrend());
        out.set("remediationDistribution", remediationDistribution());
        out.set("remediationCoverage", remediationCoverage());
        out.set("versions", versions());
        out.set("digest", digest());
        RustReference.expect("posture/decisions.json", out, PostureReferenceSetTest.class);
    }

    private static ArrayNode grades() {
        ArrayNode grades = RustReference.object().arrayNode();
        for (int score = -1; score <= 101; score++) {
            ObjectNode row = grades.addObject();
            row.put("score", score);
            row.put("grade", SecurityGrade.fromScore(score).name());
        }
        return grades;
    }

    private static ArrayNode gradeLabels() {
        ArrayNode labels = RustReference.object().arrayNode();
        for (SecurityGrade grade : SecurityGrade.values()) {
            ObjectNode row = labels.addObject();
            row.put("grade", grade.name());
            row.put("label", grade.getLabel());
            row.put("badgeColor", grade.getBadgeColor());
        }
        return labels;
    }

    private static final long[][] BACKLOGS = {
        {0, 0, 0, 0, 0, 0},
        {0, 0, 0, 1, 0, 0},
        {0, 0, 0, 4, 0, 0},
        {0, 0, 1, 0, 0, 0},
        {0, 1, 0, 0, 0, 0},
        {0, 2, 3, 0, 0, 0},
        {1, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 0, 1},
        {0, 0, 0, 0, 3, 0},
        {0, 0, 0, 0, 0, 2},
        {0, 0, 0, 10, 40, 0},
        {0, 0, 0, 80, 0, 0},
        {0, 3, 10, 20, 50, 1},
        {2, 5, 0, 0, 0, 0},
        {0, 50, 500, 0, 0, 0},
        {0, 0, 0, 0, 1, 0},
        {0, 0, 0, 0, 13, 0},
        {0, 0, 0, 0, 0, 7},
    };

    private static final double[][] WEIGHTS = {
        {25, 10, 4, 0.5, 0.125, 4, 55},
        {0, 0, 0, 0, 0, 0, 1},
        {30, 12, 5, 1, 0.25, 2, 40},
        {1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 0.001},
        {7.5, 3.3, 1.1, 0.7, 0.05, 0.9, 13.7},
    };

    private static ArrayNode candidateScores() {
        ArrayNode rows = RustReference.object().arrayNode();
        for (double[] w : WEIGHTS) {
            CandidateScore.Weights weights = new CandidateScore.Weights(w[0], w[1], w[2], w[3], w[4], w[5], w[6]);
            for (long[] c : BACKLOGS) {
                CandidateScore.Counts counts = new CandidateScore.Counts(c[0], c[1], c[2], c[3], c[4], c[5]);
                CandidateScore.Result result = CandidateScore.of(counts, weights);
                ObjectNode row = rows.addObject();
                ArrayNode weightNode = row.putArray("weights");
                for (double value : w) {
                    weightNode.add(value);
                }
                ArrayNode countNode = row.putArray("counts");
                for (long value : c) {
                    countNode.add(value);
                }
                row.put("score", result.score());
                row.put("grade", result.grade().name());
                row.put("riskPoints", result.riskPoints());
                row.put("exact", CandidateScore.exact(counts, weights));
            }
        }
        return rows;
    }

    private static ArrayNode refusedWeights() {
        double[][] cases = {
            {-1, 10, 4, 0.5, 0.125, 4, 55},
            {25, Double.NaN, 4, 0.5, 0.125, 4, 55},
            {25, 10, Double.POSITIVE_INFINITY, 0.5, 0.125, 4, 55},
            {25, 10, 4, 1_000_001, 0.125, 4, 55},
            {25, 10, 4, 0.5, -0.0001, 4, 55},
            {25, 10, 4, 0.5, 0.125, -4, 55},
            {25, 10, 4, 0.5, 0.125, 4, 0},
            {25, 10, 4, 0.5, 0.125, 4, -1},
            {25, 10, 4, 0.5, 0.125, 4, 1_000_000},
        };
        ArrayNode rows = RustReference.object().arrayNode();
        for (double[] w : cases) {
            ObjectNode row = rows.addObject();
            ArrayNode weightNode = row.putArray("weights");
            for (double value : w) {
                // Not a JSON number: the reader rebuilds NaN and the infinities from the text.
                weightNode.add(Double.toString(value));
            }
            try {
                new CandidateScore.Weights(w[0], w[1], w[2], w[3], w[4], w[5], w[6]);
                row.putNull("refused");
            } catch (InvalidInputException refused) {
                row.put("refused", refused.getMessage());
            }
        }
        return rows;
    }

    private static ArrayNode coverageCap() {
        ArrayNode rows = RustReference.object().arrayNode();
        int[][] cases = {{100, 1, 1}, {100, 2, 1}, {100, 3, 1}, {100, 3, 2}, {40, 3, 2}, {67, 3, 2}, {66, 3, 2},
            {100, 7, 1}, {100, 7, 3}, {100, 9, 5}, {100, 200, 199}, {100, 200, 1}, {90, 8, 7}, {100, 6, 5},
            {1, 10, 1}, {100, 40, 37}};
        for (int[] c : cases) {
            ObjectNode row = rows.addObject();
            row.put("score", c[0]);
            row.put("total", c[1]);
            row.put("observed", c[2]);
            row.put("capped", SecurityScorecardService.cappedToCoverage(c[0], c[1], c[2]));
        }
        return rows;
    }

    private static ArrayNode badges() {
        ArrayNode rows = RustReference.object().arrayNode();
        for (SecurityGrade grade : SecurityGrade.values()) {
            ObjectNode row = rows.addObject();
            row.put("status", grade.getLabel());
            row.put("color", grade.getBadgeColor());
            row.put("svg", SvgBadgeGenerator.generateBadge("security grade", grade.getLabel(), grade.getBadgeColor()));
        }
        ObjectNode unknown = rows.addObject();
        unknown.put("status", "unknown");
        unknown.put("color", "#555");
        unknown.put("svg", SvgBadgeGenerator.generateBadge("security grade", "unknown", "#555"));
        return rows;
    }

    private static Instant at(String text) {
        return text == null ? null : Instant.parse(text);
    }

    /** Lifespans and observations alike: first seen, resolved — some at the edges of a day, some backwards. */
    private static final String[][] SPANS = {
        {"2026-03-01T10:00:00Z", null},
        {"2026-03-02T00:00:00Z", "2026-03-04T00:00:00Z"},
        {"2026-03-03T23:59:59.999999999Z", "2026-03-04T00:00:00Z"},
        {"2026-02-20T08:30:00Z", "2026-03-05T12:00:00.5Z"},
        {"2026-03-05T12:00:00Z", "2026-03-05T11:00:00Z"},
        {null, "2026-03-05T00:00:00Z"},
        {"2026-03-06T00:00:00Z", null},
        {"2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"},
        {"2026-03-07T23:00:00Z", "2026-03-08T00:00:00Z"},
        {"2026-03-01T00:00:00.000000001Z", "2026-03-07T17:45:12.25Z"},
    };

    private static final String[] SEVERITIES = {"critical", "HIGH", null, "Medium", "low", "critical", "unknown",
        "high", "LOW", "weird"};

    private static ArrayNode backlogTrend() {
        List<BacklogTrend.Lifespan> lifespans = new ArrayList<>();
        for (String[] span : SPANS) {
            lifespans.add(new BacklogTrend.Lifespan(at(span[0]), at(span[1])));
        }
        ArrayNode cases = RustReference.object().arrayNode();
        String[][] windows = {{"2026-03-01", "2026-03-08"}, {"2026-03-04", "2026-03-04"}, {"2026-02-25", "2026-03-02"},
            {"2025-12-30", "2026-01-02"}};
        for (String[] window : windows) {
            BacklogTrend.Series series =
                    BacklogTrend.over(lifespans, LocalDate.parse(window[0]), LocalDate.parse(window[1]));
            ObjectNode row = cases.addObject();
            row.put("from", window[0]);
            row.put("to", window[1]);
            ArrayNode points = row.putArray("points");
            for (BacklogTrend.Point point : series.points()) {
                ObjectNode p = points.addObject();
                p.put("day", point.day().toString());
                p.put("open", point.open());
                p.put("opened", point.opened());
                p.put("resolved", point.resolved());
            }
            if (series.meanDaysToResolve().isPresent()) {
                row.put("meanDaysToResolve", series.meanDaysToResolve().get());
            } else {
                row.putNull("meanDaysToResolve");
            }
            row.put("resolvedInWindow", series.resolvedInWindow());
        }
        return cases;
    }

    private static ArrayNode postureTrend() {
        List<PostureTrendAnalytics.IssueObservation> observations = new ArrayList<>();
        for (int index = 0; index < SPANS.length; index++) {
            observations.add(new PostureTrendAnalytics.IssueObservation(
                    (long) index % 3, index % 2 == 0 ? "REPOSITORY" : "CONTAINER", "target " + index % 3,
                    SEVERITIES[index], at(SPANS[index][0]), at(SPANS[index][1])));
        }
        ArrayNode cases = RustReference.object().arrayNode();
        Object[][] runs = {{7, "2026-03-08T09:15:00Z"}, {30, "2026-03-08T00:00:00Z"}, {7, "2026-03-04T23:59:59Z"},
            {10, "2026-01-05T00:00:00Z"}};
        for (Object[] run : runs) {
            int window = (Integer) run[0];
            Instant now = Instant.parse((String) run[1]);
            Instant start = PostureTrendAnalytics.windowStart(window, now);
            List<PostureTrendAnalytics.IssueObservation> touching = observations.stream()
                    .filter(obs -> PostureTrendAnalytics.touchesWindow(obs, start))
                    .toList();
            PostureTrendAnalytics analytics = PostureTrendAnalytics.calculate(window, now, touching, List.of());
            ObjectNode row = cases.addObject();
            row.put("windowDays", window);
            row.put("now", run[1].toString());
            ArrayNode touchingNode = row.putArray("touching");
            touching.forEach(obs -> touchingNode.add(observations.indexOf(obs)));
            putNullable(row, "overallMttrDays", analytics.overallMttrDays());
            ObjectNode bySeverity = row.putObject("mttrBySeverity");
            analytics.mttrBySeverity().forEach((severity, days) -> {
                if (days == null) {
                    bySeverity.putNull(severity);
                } else {
                    bySeverity.put(severity, days);
                }
            });
            row.put("totalOpenedInWindow", analytics.totalOpenedInWindow());
            row.put("totalResolvedInWindow", analytics.totalResolvedInWindow());
            row.put("netResolutionRatePercentage", analytics.netResolutionRatePercentage());
            ArrayNode daily = row.putArray("dailySeries");
            for (PostureTrendAnalytics.DailyPosturePoint point : analytics.dailySeries()) {
                ObjectNode p = daily.addObject();
                p.put("date", point.date().toString());
                p.put("openBacklog", point.openBacklog());
                p.put("newlyDiscovered", point.newlyDiscovered());
                p.put("newlyResolved", point.newlyResolved());
                putNullable(p, "rollingMttrDays", point.rollingMttrDays());
            }
        }
        // `roundDays`: Java's half-up rounding at one decimal, at the points where a half is not one in binary.
        ArrayNode rounded = RustReference.object().arrayNode();
        for (double days : new double[] {0.05, 0.15, 0.25, 0.35, 1.45, 2.55, 1.0 / 3, 2.0 / 3, 12.349999, 99.95,
            -0.05, 0, 1e-9}) {
            ObjectNode r = rounded.addObject();
            r.put("days", days);
            r.put("rounded", PostureTrendAnalytics.roundDays(days));
        }
        ObjectNode last = cases.addObject();
        last.set("roundDays", rounded);
        return cases;
    }

    private static void putNullable(ObjectNode node, String field, Double value) {
        if (value == null) {
            node.putNull(field);
        } else {
            node.put(field, value);
        }
    }

    private static ArrayNode remediationDistribution() {
        Map<Severity, Duration> windows = new LinkedHashMap<>();
        windows.put(Severity.CRITICAL, Duration.ofDays(15));
        windows.put(Severity.HIGH, Duration.ofDays(30));
        windows.put(Severity.MEDIUM, Duration.ofDays(0));
        windows.put(Severity.LOW, Duration.ofDays(180));
        RemediationSla sla = new RemediationSla(windows);
        long day = 86_400;
        List<RemediationDistribution.Resolved> resolved = List.of(
                new RemediationDistribution.Resolved(Severity.CRITICAL, 3 * day),
                new RemediationDistribution.Resolved(Severity.CRITICAL, 15 * day),
                new RemediationDistribution.Resolved(Severity.CRITICAL, 15 * day + 1),
                new RemediationDistribution.Resolved(Severity.CRITICAL, 40 * day + 4321),
                new RemediationDistribution.Resolved(Severity.HIGH, 1),
                new RemediationDistribution.Resolved(Severity.MEDIUM, 100 * day),
                new RemediationDistribution.Resolved(Severity.UNKNOWN, 2 * day),
                new RemediationDistribution.Resolved(Severity.LOW, 7 * day + 43_200),
                new RemediationDistribution.Resolved(Severity.LOW, 9 * day),
                new RemediationDistribution.Resolved(Severity.LOW, 181 * day),
                new RemediationDistribution.Resolved(null, day));
        List<RemediationDistribution.Open> open = List.of(
                new RemediationDistribution.Open(Severity.CRITICAL, 4, 2, 31L),
                new RemediationDistribution.Open(Severity.HIGH, 1, 0, 2L),
                new RemediationDistribution.Open(Severity.LOW, 9, 1, 31L),
                new RemediationDistribution.Open(Severity.NEGLIGIBLE, 3, 0, null));
        ArrayNode cases = RustReference.object().arrayNode();
        cases.add(distribution(RemediationDistribution.calculate(30, sla, resolved, open)));
        cases.add(distribution(RemediationDistribution.calculate(7, RemediationSla.DEFAULT, List.of(), List.of())));
        cases.add(distribution(RemediationDistribution.calculate(
                90, RemediationSla.DEFAULT, resolved.subList(0, 5), open.subList(1, 2))));
        return cases;
    }

    private static ObjectNode distribution(RemediationDistribution distribution) {
        ObjectNode row = RustReference.object();
        row.put("windowDays", distribution.windowDays());
        ArrayNode bySeverity = row.putArray("bySeverity");
        for (RemediationDistribution.BySeverity line : distribution.bySeverity()) {
            ObjectNode l = bySeverity.addObject();
            l.put("severity", line.severity().wireName());
            l.put("windowDays", line.windowDays());
            l.put("withinSla", line.withinSla());
            l.put("late", line.late());
            putNullable(l, "percentageWithinSla", line.percentageWithinSla());
            putNullable(l, "medianDays", line.medianDays());
            putNullable(l, "ninetiethDays", line.ninetiethDays());
            l.put("openOverdue", line.openOverdue());
            if (line.oldestOpenDays() == null) {
                l.putNull("oldestOpenDays");
            } else {
                l.put("oldestOpenDays", line.oldestOpenDays());
            }
        }
        if (distribution.oldestOpenDays() == null) {
            row.putNull("oldestOpenDays");
        } else {
            row.put("oldestOpenDays", distribution.oldestOpenDays());
        }
        row.put("oldestOpenSeverity",
                distribution.oldestOpenSeverity() == null ? null : distribution.oldestOpenSeverity().wireName());
        return row;
    }

    private static ArrayNode remediationCoverage() {
        List<List<RemediationCoverage.OpenFamily>> cases = List.of(
                List.of(),
                List.of(new RemediationCoverage.OpenFamily("vulnerability", 10, 0)),
                List.of(new RemediationCoverage.OpenFamily("vulnerability", 10, 3),
                        new RemediationCoverage.OpenFamily("secret", 0, 4),
                        new RemediationCoverage.OpenFamily("sast", 1, 3),
                        new RemediationCoverage.OpenFamily("ai_review", 5, 5),
                        new RemediationCoverage.OpenFamily("plugin", 1, 0),
                        new RemediationCoverage.OpenFamily("imported", 2, 2),
                        new RemediationCoverage.OpenFamily("iac", 0, 4),
                        new RemediationCoverage.OpenFamily("eol", 0, 0),
                        new RemediationCoverage.OpenFamily("something_new", 1, 1)),
                List.of(new RemediationCoverage.OpenFamily("license", 2, 0),
                        new RemediationCoverage.OpenFamily("quality", 1, 1),
                        new RemediationCoverage.OpenFamily("vulnerability", 0, 2)));
        ArrayNode rows = RustReference.object().arrayNode();
        for (List<RemediationCoverage.OpenFamily> families : cases) {
            ObjectNode row = rows.addObject();
            ArrayNode input = row.putArray("families");
            for (RemediationCoverage.OpenFamily family : families) {
                ObjectNode f = input.addObject();
                f.put("type", family.type());
                f.put("packageNamed", family.packageNamed());
                f.put("unnamed", family.unnamed());
            }
            RemediationCoverage coverage = RemediationCoverage.of(families);
            row.put("openFindings", coverage.openFindings());
            row.put("addressableByUpgrade", coverage.addressableByUpgrade());
            row.put("beyondUpgrades", coverage.beyondUpgrades());
            ArrayNode gaps = row.putArray("gaps");
            coverage.gaps().forEach(gap -> {
                ObjectNode g = gaps.addObject();
                g.put("family", gap.family());
                g.put("findings", gap.findings());
            });
        }
        return rows;
    }

    private static ArrayNode versions() {
        String[][] sets = {
            {},
            {"1.2.3"},
            {"1.2.10", "1.2.9", "1.2.9.1"},
            {"2.17", "2.17.0", " 2.17.1 ", ""},
            {"2.0", "2.rc1", "2.RC2"},
            {"1.0.0-beta", "1.0.0-alpha", "1.0.0"},
            {"20240101123456789012345", "20240101123456789012344", "9"},
            {"v1.2", "1.3", "V1.10"},
            {"1_2", "1+3", "1-1"},
            {"  ", "\t"},
            {"1.2.3, 1.2.4", "1.10"},
        };
        ArrayNode rows = RustReference.object().arrayNode();
        for (String[] set : sets) {
            ObjectNode row = rows.addObject();
            ArrayNode input = row.putArray("candidates");
            for (String candidate : set) {
                input.add(candidate);
            }
            row.put("highest", Versions.highest(List.of(set)).orElse(null));
        }
        String[] lists = {null, "", " , ", "1.2.3", "1.2.3,1.2.4", " 2.0 ,, 3.0 ", "a,b , c"};
        for (String list : lists) {
            ObjectNode row = rows.addObject();
            row.put("split", list);
            ArrayNode parts = row.putArray("parts");
            Versions.split(list).forEach(parts::add);
        }
        return rows;
    }

    private static ArrayNode digest() {
        ArrayNode rows = RustReference.object().arrayNode();
        Map<String, Long> backlog = new LinkedHashMap<>();
        backlog.put("critical", 2L);
        backlog.put("high", 11L);
        backlog.put("unknown", 1L);
        Object[][] cases = {
            {"2026-03-02", 14L, backlog, 3L, 5L, 4L, 2, 9, 0L, 0L, Optional.of(3.25)},
            {"2026-03-09", 0L, Map.of(), 0L, 0L, 0L, 0, 0, 0L, 0L, Optional.empty()},
            {"2026-03-16", 7L, backlog, 1L, 0L, 0L, 1, 4, 2L, 1L, Optional.of(0.05)},
            {"2026-03-23", 7L, backlog, 1L, 2L, 0L, 1, 4, 0L, 3L, Optional.of(12.35)},
        };
        for (Object[] c : cases) {
            @SuppressWarnings("unchecked")
            Map<String, Long> bySeverity = (Map<String, Long>) c[2];
            @SuppressWarnings("unchecked")
            Optional<Double> mean = (Optional<Double>) c[10];
            PostureDigest digest = PostureDigest.of(LocalDate.parse((String) c[0]), new PostureDigest.Counts(
                    (Long) c[1], bySeverity, (Long) c[3], (Long) c[4], (Long) c[5], (Integer) c[6], (Integer) c[7],
                    (Long) c[8], (Long) c[9], mean));
            ObjectNode row = rows.addObject();
            row.put("weekOf", (String) c[0]);
            row.put("openTotal", (Long) c[1]);
            ObjectNode severities = row.putObject("backlogBySeverity");
            bySeverity.forEach(severities::put);
            row.put("openedThisWeek", (Long) c[3]);
            row.put("resolvedThisWeek", (Long) c[4]);
            row.put("overdueCount", (Long) c[5]);
            row.put("failingTargets", (Integer) c[6]);
            row.put("totalTargets", (Integer) c[7]);
            row.put("neverScanned", (Long) c[8]);
            row.put("lastScanFailed", (Long) c[9]);
            putNullable(row, "meanDaysToResolve", mean.orElse(null));
            row.put("text", digest.text());
            row.put("subject", digest.asSubject());
            row.put("plainText", digest.asPlainText());
        }
        return rows;
    }
}
