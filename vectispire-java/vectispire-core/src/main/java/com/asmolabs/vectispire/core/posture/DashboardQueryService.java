package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.trends.BacklogTrend;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.vectispire.core.gate.GateService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.SlaService;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import com.asmolabs.vectispire.core.posture.internal.PostureScoreboards;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;

/**
 * The figures the dashboard shows, read once and narrowed by the caller's visibility.
 *
 * <p><b>It computes no aggregate of its own.</b> The posture comes from {@link GateService},
 * exactly the one the security screen shows and {@code POST /gate} evaluates; the backlog comes
 * from the issue repository through {@link IssueFilters}. A dashboard that reimplements its
 * figures ends up displaying different ones from the detail screens — and it is the one people
 * believe, because it is the home page.
 */
@Service
public class DashboardQueryService {

    private static final int RECENT_SCANS = 8;

    /**
     * The longest series this service will draw.
     *
     * <p>A ceiling because the window is also the number of days iterated over every issue in
     * scope: `days=100000` is not an attack, it is a client asking for "everything" without
     * knowing what everything costs.
     */
    private static final int MAX_TREND_DAYS = 365;

    private final GateService gate;
    private final IssueCatalog issues;
    private final ScanCatalog scans;
    private final TargetNaming naming;
    private final SlaService sla;

    /** Injected rather than {@code Instant.now()}, so a test can pin what "today" means. */
    private final Clock clock;

    public DashboardQueryService(
            GateService gate, IssueCatalog issues, ScanCatalog scans, TargetNaming naming, SlaService sla, Clock clock) {
        this.gate = gate;
        this.issues = issues;
        this.scans = scans;
        this.naming = naming;
        this.sla = sla;
        this.clock = clock;
    }

    /**
     * @param targetName what the target is called. <b>The ids alone were what the screen
     *     printed</b> — "Container 3" — which names nothing an operator recognises and cannot
     *     be matched against the target they came here about
     */
    public record RecentScan(
            Long id,
            Long repoId,
            Long containerId,
            String targetKind,
            String targetName,
            String status,
            int findingsCount,
            String error,
            Instant createdAt) {}

    /**
     * Everything the home page is made of, before it is spelled for the wire.
     *
     * @param overdueCount open issues past their remediation window. Zero when every window is
     *     disabled, which is indistinguishable here from "nothing is late"
     * @param failing the targets that fail their policy, and only those
     */
    public record Overview(
            SecurityOverview.Overview posture,
            long overdueCount,
            Map<String, Long> backlogBySeverity,
            long qualityTotal,
            List<SecurityOverview.TargetPosture> failing,
            List<RecentScan> recentScans) {}

    public Overview overview(Visibility allowed) {
        SecurityOverview.Overview posture = gate.overview(allowed);
        return new Overview(
                posture,
                sla.countOverdue(allowed),
                backlogBySeverity(allowed),
                // Within the allowance, like every other figure here. It counted every target's
                // open quality issues, so a reader given one repository saw the size of the
                // deployment's quality backlog beside their own numbers.
                issues.count(new IssueFilters(
                                IssueState.OPEN.wireName(), null, FindingType.QUALITY.wireName(),
                                null, null, null, false, false, null, allowed)),
                posture.targets().stream().filter(target -> !target.passed()).toList(),
                recentScans(allowed));
    }

    /** @param day an ISO date, UTC — the axis has to mean the same thing in two timezones */
    public record TrendPoint(String day, long open, long opened, long resolved) {}

    /**
     * @param meanDaysToResolve null when nothing was resolved in the window. <b>Not zero</b>: zero
     *     reads as "everything is fixed the day it appears", which is the opposite of "there is
     *     nothing to measure"
     * @param resolvedInWindow the population behind the mean, so a reader can see whether it rests
     *     on three issues or three hundred — an average with no denominator is a number people
     *     quote and should not
     */
    public record Trends(
            List<TrendPoint> points,
            @JsonProperty("mean_days_to_resolve") Double meanDaysToResolve,
            @JsonProperty("resolved_in_window") int resolvedInWindow) {}

    /**
     * The backlog over time — see {@code DashboardController#trends} for why the arithmetic is
     * in {@link BacklogTrend} rather than in SQL, and what that costs.
     */
    public Trends trends(int days, Visibility allowed) {
        // Clamped rather than refused: a chart is not a place to fail a request over a query
        // string, and the ceiling exists because the window is also the number of days iterated.
        int window = Math.clamp(days, 1, MAX_TREND_DAYS);

        LocalDate to = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        LocalDate from = to.minusDays(window - 1L);

        // Every issue, not only the open ones: an issue resolved inside the window has to be
        // counted as open on the days before it was resolved, or the curve would start at today's
        // backlog and pretend the history was always this good.
        // **Two columns, not every row.** Read as entities this loaded one managed object per
        // issue in the estate to take two timestamps off each — measured linear, at a constant
        // query count. The projection asks the database for exactly what the curve is made of.
        List<BacklogTrend.Lifespan> lifespans = issues
                .rows(new IssueFilters(null, null, null, null, null, null, false, false, null, allowed), IssueRows.Lifespan.class)
                .stream()
                .map(row -> new BacklogTrend.Lifespan(row.firstSeenAt(), row.resolvedAt()))
                .toList();

        BacklogTrend.Series series = BacklogTrend.over(lifespans, from, to);
        return new Trends(
                series.points().stream()
                        .map(point -> new TrendPoint(
                                point.day().toString(), point.open(), point.opened(), point.resolved()))
                        .toList(),
                series.meanDaysToResolve().orElse(null),
                series.resolvedInWindow());
    }

    public PostureTrendAnalytics postureAnalytics(int days, Visibility allowed) {
        int window = Math.clamp(days, 7, MAX_TREND_DAYS);

        // **Two reads with different shapes, because the page asks two different questions.**
        //
        // The curve is about a window: `touchesWindow` proves that an issue resolved before the
        // window opened cannot move any point on it, so the series is drawn from the issues that
        // touch the window rather than from the estate. The old read took every issue ever
        // recorded and then walked that whole list again *for each day* of the window — a
        // hundred thousand issues over ninety days is nine million passes for one page.
        //
        // The scoreboard is about all time and cannot be windowed at all: it reports what a
        // target has resolved since it was added. That half is counted by the database instead
        // — `group by` for the open backlog, and the closed issues narrowed to the two instants
        // an average needs.
        IssueFilters visible =
                new IssueFilters(null, null, null, null, null, null, false, false, null, allowed);

        Instant now = clock.instant();
        Instant windowStart = PostureTrendAnalytics.windowStart(window, now);

        List<IssueRows.Observation> touching = issues.rows(
                visible.touching(windowStart), IssueRows.Observation.class);

        // **The open backlog leaves settled triage out; the curve and the resolved half do not.**
        // The ranking used to count every unresolved row, so a target whose team had argued each
        // finding not affected kept the grade of one that had looked at nothing — and disagreed
        // with the scorecard and the gate about the same rows. `not_affected` and `fixed` go, as
        // they do there; `pending_approval` and any status this version does not know stay. The
        // curve is a record of what appeared and closed, which a triage decision does not rewrite.
        List<IssueAggregates.TargetSeverityCount> openCounts = issues.countOpenByTargetAndSeverity(
                new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), allowed));
        List<IssueAggregates.TargetResolutions> resolved = issues.countResolvedByTarget(visible);

        // Named once for both halves: the curve needs no names at all, but the scoreboard does,
        // and resolving them twice would be two queries for one answer.
        TargetNaming.Names names = naming.forIds(
                repositoryIds(touching, openCounts, resolved), containerIds(touching, openCounts, resolved));

        List<PostureTrendAnalytics.IssueObservation> observations = touching.stream()
                .map(i -> new PostureTrendAnalytics.IssueObservation(
                        i.repoId() != null ? i.repoId() : i.containerId(),
                        i.repoId() != null ? "REPOSITORY" : "CONTAINER",
                        names.of(i.repoId(), i.containerId()),
                        i.severity() != null ? i.severity() : "MEDIUM",
                        i.firstSeenAt(),
                        i.resolvedAt()))
                .toList();

        return PostureTrendAnalytics.calculate(
                window, now, observations, PostureScoreboards.from(openCounts, resolved, names));
    }

    /** An `in` list that matches nothing when there is nothing to match. */
    private static List<Long> orNone(List<Long> ids) {
        return ids.isEmpty() ? List.of(-1L) : ids;
    }

    /**
     * The open backlog per severity, <b>within what the caller may see</b>.
     *
     * <p>It was a single grouped query with no visibility clause, which made this the one figure
     * on a narrowed dashboard that counted everything: a reader assigned to one repository read
     * the whole deployment's severity breakdown beside a posture that was correctly narrowed.
     * Aggregates are not exempt — "how much is there that I am not shown" is information too.
     *
     * <p>The cost is one indexed count per severity instead of one grouped scan. That is the
     * price of the filter being expressed once, in {@link IssueFilters}, rather than a second
     * time in a hand-written {@code group by} that would have to grow its own visibility clause.
     *
     * <p><b>Settled triage is left out</b>, as in every other figure of risk here — the maturity
     * ranking, the overdue count, the scorecard. Each count links to the issues list with
     * {@code unsettled=true}, which applies the same clause, so the figure and the rows it opens
     * agree; that link is what made the exclusion possible here, where it had been held back.
     */
    private Map<String, Long> backlogBySeverity(Visibility allowed) {
        Map<String, Long> counts = new HashMap<>();
        for (Severity severity : Severity.values()) {
            long count = issues.count(new IssueFilters(
                            IssueState.OPEN.wireName(),
                            severity.wireName(),
                            null, null, null, null, false, false, null, true, Map.of(), allowed));
            if (count > 0) {
                // Absent rather than zero, as the grouped query left it: the screen reads this as
                // a map and a zero would add a row for every severity nobody has.
                counts.put(severity.wireName(), count);
            }
        }
        return counts;
    }

    /**
     * The last scans the caller may see.
     *
     * <p>They were the deployment's last scans, whoever asked: target names, statuses and errors
     * of repositories a restricted reader was never given, on the home page.
     */
    private List<RecentScan> recentScans(Visibility allowed) {
        List<ScanView> recent = switch (allowed) {
            case Visibility.Everything everything -> scans.history(null, null, RECENT_SCANS);
            case Visibility.Only only -> {
                List<Long> repoIds = only.targets().stream()
                        .filter(t -> t instanceof ScanTarget.Repository)
                        .map(t -> ((ScanTarget.Repository) t).id()).toList();
                List<Long> containerIds = only.targets().stream()
                        .filter(t -> t instanceof ScanTarget.Container)
                        .map(t -> ((ScanTarget.Container) t).id()).toList();
                yield repoIds.isEmpty() && containerIds.isEmpty()
                        ? List.of()
                        : scans.recentWithin(orNone(repoIds), orNone(containerIds), RECENT_SCANS);
            }
        };
        TargetNaming.Names names = naming.forIds(
                idsOf(recent, ScanView::repoId), idsOf(recent, ScanView::containerId));

        return recent.stream().map(scan -> recentOf(scan, names)).toList();
    }

    private static List<Long> idsOf(List<ScanView> scans, Function<ScanView, Long> id) {
        return scans.stream().map(id).filter(Objects::nonNull).distinct().toList();
    }

    /**
     * The target, with the branch when there is one.
     *
     * <p><b>The branch comes from the scan, not from the repository.</b> A repository's branch
     * can be changed after the fact, and reading it from there would relabel a finished scan
     * with a branch it never ran on — the one kind of error a history must not make.
     *
     * <p>Images are left alone: their scans carry {@code n/a} in that column, and "alpine:3.20 -
     * n/a" is worse than no branch at all.
     */
    private static String scanTargetName(ScanView scan, TargetNaming.Names names) {
        String name = names.of(scan.repoId(), scan.containerId());
        if (name == null || scan.containerId() != null) {
            return name;
        }
        String branch = scan.branch();
        return branch == null || branch.isBlank() ? name : name + " — " + branch;
    }

    private static RecentScan recentOf(ScanView scan, TargetNaming.Names names) {
        return new RecentScan(
                scan.id(),
                scan.repoId(),
                scan.containerId(),
                names.kindOf(scan.containerId()),
                scanTargetName(scan, names),
                scan.status(),
                scan.findingsCount(),
                scan.error(),
                scan.createdAt());
    }

    private static List<Long> repositoryIds(
            List<IssueRows.Observation> touching,
            List<IssueAggregates.TargetSeverityCount> openCounts,
            List<IssueAggregates.TargetResolutions> resolved) {

        return Stream.of(
                        touching.stream().map(IssueRows.Observation::repoId),
                        openCounts.stream().map(IssueAggregates.TargetSeverityCount::repoId),
                        resolved.stream().map(IssueAggregates.TargetResolutions::repoId))
                .flatMap(ids -> ids)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    private static List<Long> containerIds(
            List<IssueRows.Observation> touching,
            List<IssueAggregates.TargetSeverityCount> openCounts,
            List<IssueAggregates.TargetResolutions> resolved) {

        return Stream.of(
                        touching.stream().map(IssueRows.Observation::containerId),
                        openCounts.stream().map(IssueAggregates.TargetSeverityCount::containerId),
                        resolved.stream().map(IssueAggregates.TargetResolutions::containerId))
                .flatMap(ids -> ids)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }
}
