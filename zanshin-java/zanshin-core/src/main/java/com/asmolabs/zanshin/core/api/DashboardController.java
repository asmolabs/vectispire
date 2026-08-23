package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.gate.GateVerdict;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.common.domain.trends.BacklogTrend;
import com.asmolabs.zanshin.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.IssueFilters;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.services.GateService;
import com.asmolabs.zanshin.core.services.SlaService;
import com.asmolabs.zanshin.core.services.TargetNaming;
import com.asmolabs.zanshin.core.services.VisibilityService;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Limit;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The dashboard.
 *
 * <p><b>It computes no aggregate of its own.</b> The posture comes from {@link GateService},
 * exactly the one the security screen shows and {@code POST /gate} evaluates; the backlog comes
 * from the issue repository. A dashboard that reimplements its figures ends up displaying
 * different ones from the detail screens — and it is the one people believe, because it is the
 * home page.
 */
@RestController
@RequestMapping("/api/v1/dashboard")
@RequiresAccount
public class DashboardController {

    private static final int RECENT_SCANS = 8;

    /**
     * The longest series this route will draw.
     *
     * <p>A ceiling because the window is also the number of days iterated over every issue in
     * scope: `days=100000` is not an attack, it is a client asking for "everything" without
     * knowing what everything costs.
     */
    private static final int MAX_TREND_DAYS = 365;

    private final GateService gate;
    private final Issues issues;
    private final Scans scans;
    private final TargetNaming naming;

    private final VisibilityService visibility;
    private final SlaService sla;

    /** Injected rather than {@code Instant.now()}, so a test can pin what "today" means. */
    private final Clock clock;

    public DashboardController(
            GateService gate,
            Issues issues,
            Scans scans,
            TargetNaming naming,
            VisibilityService visibility,
            SlaService sla,
            Clock clock) {
        this.gate = gate;
        this.issues = issues;
        this.scans = scans;
        this.naming = naming;
        this.visibility = visibility;
        this.sla = sla;
        this.clock = clock;
    }

    /**
     * @param neverScannedCount a target nobody has scanned passes every policy: its lack of
     *     findings is not a lack of problems. Its own figure, therefore
     * @param overdueCount open issues past their remediation window — the figure a security
     *     officer is asked for, and the only one on this record that is about <em>time</em>
     *     rather than about quantity. Zero when every window is disabled, which is
     *     indistinguishable here from "nothing is late": the remediation section of the settings
     *     screen is where that distinction lives
     */
    public record Posture(
            int failingCount,
            int totalCount,
            long kevCount,
            long neverScannedCount,
            long lastScanFailedCount,
            long overdueCount) {}

    public record FailingTarget(
            String kind, Long targetId, String name, boolean observed, List<GateVerdict.Violation> violations) {}

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
     * @param qualityTotal apart, and never mixed into the security backlog: it blocks nothing
     * @param failing the targets in failure, so there is something to act on from here
     */
    public record Overview(
            Posture posture,
            Map<String, Long> backlogBySeverity,
            long qualityTotal,
            List<FailingTarget> failing,
            List<RecentScan> recentScans) {}

    @GetMapping
    public Overview overview(@AuthenticationPrincipal ZanshinPrincipal principal) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        SecurityOverview.Overview posture = gate.overview(allowed);

        return new Overview(
                new Posture(
                        posture.failingCount(),
                        posture.totalCount(),
                        posture.kevCount(),
                        posture.neverScannedCount(),
                        posture.lastScanFailedCount(),
                        sla.countOverdue(allowed)),
                backlogBySeverity(allowed),
                issues.countByStateAndType(IssueState.OPEN.wireName(), FindingType.QUALITY.wireName()),
                posture.targets().stream()
                        .filter(target -> !target.passed())
                        .map(DashboardController::failingOf)
                        .toList(),
                recentScans());
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
     * The backlog over time.
     *
     * <p><b>Why this route exists.</b> Everything else on this screen is a snapshot, so the
     * question a security officer is actually asked — is this getting better or worse — had no
     * answer anywhere in the product. The counts say how much; only a series says which direction.
     *
     * <p><b>Narrowed by visibility like every other read.</b> Stated because the one aggregate that
     * ever leaked here was the one that returned numbers rather than rows, and the shape of that
     * mistake is exactly this: a series feels like a chart rather than like data somebody owns.
     *
     * <p><b>All the date arithmetic is in {@link BacklogTrend}, not in SQL.</b> Four engines spell
     * date truncation four ways, and the grouped query that is wrong would be wrong on the engine
     * nobody develops on. The database returns two timestamps per issue; the buckets are counted
     * in a pure function with its own suite.
     *
     * <p>The cost is loading those two timestamps for the issues in scope rather than aggregating
     * server-side — accepted, and named here so the next person knows what to change if it starts
     * to hurt: a projection, then a cache, and only then a dialect-specific {@code group by}.
     */
    @GetMapping("/trends")
    public Trends trends(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @RequestParam(required = false, defaultValue = "90") int days) {

        // Clamped rather than refused: a chart is not a place to fail a request over a query
        // string, and the ceiling exists because the window is also the number of days iterated.
        int window = Math.clamp(days, 1, MAX_TREND_DAYS);
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());

        LocalDate to = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        LocalDate from = to.minusDays(window - 1L);

        // Every issue, not only the open ones: an issue resolved inside the window has to be
        // counted as open on the days before it was resolved, or the curve would start at today's
        // backlog and pretend the history was always this good.
        List<BacklogTrend.Lifespan> lifespans = issues
                .findAll(new IssueFilters(null, null, null, null, null, null, false, false, null, allowed)
                        .toSpecification())
                .stream()
                .map(issue -> new BacklogTrend.Lifespan(issue.getFirstSeenAt(), issue.getResolvedAt()))
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

    @GetMapping("/posture-analytics")
    public PostureTrendAnalytics postureAnalytics(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @RequestParam(required = false, defaultValue = "30") int days) {

        int window = Math.clamp(days, 7, MAX_TREND_DAYS);
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());

        List<com.asmolabs.zanshin.core.persistence.IssueEntity> allIssues = issues
                .findAll(new IssueFilters(null, null, null, null, null, null, false, false, null, allowed)
                        .toSpecification());

        List<Long> repoIds = allIssues.stream().map(com.asmolabs.zanshin.core.persistence.IssueEntity::getRepoId).filter(java.util.Objects::nonNull).distinct().toList();
        List<Long> containerIds = allIssues.stream().map(com.asmolabs.zanshin.core.persistence.IssueEntity::getContainerId).filter(java.util.Objects::nonNull).distinct().toList();
        TargetNaming.Names names = naming.forIds(repoIds, containerIds);

        List<PostureTrendAnalytics.IssueObservation> observations = allIssues.stream()
                .map(i -> new PostureTrendAnalytics.IssueObservation(
                        i.getRepoId() != null ? i.getRepoId() : i.getContainerId(),
                        i.getRepoId() != null ? "REPOSITORY" : "CONTAINER",
                        names.of(i.getRepoId(), i.getContainerId()),
                        i.getSeverity() != null ? i.getSeverity() : "MEDIUM",
                        i.getFirstSeenAt(),
                        i.getResolvedAt()))
                .toList();

        return PostureTrendAnalytics.calculate(window, clock.instant(), observations);
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
     */
    private Map<String, Long> backlogBySeverity(Visibility allowed) {
        Map<String, Long> counts = new HashMap<>();
        for (Severity severity : Severity.values()) {
            long count = issues.count(new IssueFilters(
                            IssueState.OPEN.wireName(),
                            severity.wireName(),
                            null, null, null, null, false, false, null, allowed)
                    .toSpecification());
            if (count > 0) {
                // Absent rather than zero, as the grouped query left it: the screen reads this as
                // a map and a zero would add a row for every severity nobody has.
                counts.put(severity.wireName(), count);
            }
        }
        return counts;
    }

    private List<RecentScan> recentScans() {
        List<ScanEntity> recent = scans.findHistory(null, null, Limit.of(RECENT_SCANS));
        TargetNaming.Names names = naming.forIds(
                idsOf(recent, ScanEntity::getRepoId), idsOf(recent, ScanEntity::getContainerId));

        return recent.stream().map(scan -> recentOf(scan, names)).toList();
    }

    private static List<Long> idsOf(List<ScanEntity> scans, java.util.function.Function<ScanEntity, Long> id) {
        return scans.stream().map(id).filter(java.util.Objects::nonNull).distinct().toList();
    }

    private static FailingTarget failingOf(SecurityOverview.TargetPosture posture) {
        return new FailingTarget(
                posture.target() instanceof ScanTarget.Repository ? "repository" : "container",
                switch (posture.target()) {
                    case ScanTarget.Repository repository -> repository.id();
                    case ScanTarget.Container container -> container.id();
                },
                posture.name(),
                posture.observed(),
                posture.verdict().violations());
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
    private static String scanTargetName(ScanEntity scan, TargetNaming.Names names) {
        String name = names.of(scan.getRepoId(), scan.getContainerId());
        if (name == null || scan.getContainerId() != null) {
            return name;
        }
        String branch = scan.getBranch();
        return branch == null || branch.isBlank() ? name : name + " — " + branch;
    }

    private static RecentScan recentOf(ScanEntity scan, TargetNaming.Names names) {
        return new RecentScan(
                scan.getId(),
                scan.getRepoId(),
                scan.getContainerId(),
                names.kindOf(scan.getContainerId()),
                scanTargetName(scan, names),
                scan.getStatus(),
                scan.getFindingsCount(),
                scan.getError(),
                scan.getCreatedAt());
    }
}
