package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.trends.BacklogTrend;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.DashboardQueryService;
import com.asmolabs.vectispire.core.services.GateService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import java.util.List;
import java.util.Map;
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
 * home page. The reads are {@link DashboardQueryService}'s; what is left here is their spelling.
 */
@RestController
@RequestMapping("/api/v1/dashboard")
@RequiresAccount
public class DashboardController {

    private final DashboardQueryService dashboard;
    private final VisibilityService visibility;

    public DashboardController(DashboardQueryService dashboard, VisibilityService visibility) {
        this.dashboard = dashboard;
        this.visibility = visibility;
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

    /**
     * @param violations the violations <b>as the wire spells them</b>. This carried the domain
     *     record, whose {@code rule} serialises as the enum — {@code KEV} — while the screen
     *     compares {@code violation.rule === 'kev'}. Every violation on the dashboard was therefore
     *     tagged "Severity", including the KEV ones, which is the tag the row exists to make stand
     *     out. {@link ViolationView} is the spelling every other route already sends, and its own
     *     documentation says the dashboard compares lowercase; it just was not used here.
     */
    public record FailingTarget(
            String kind, Long targetId, String name, boolean observed, List<ViolationView> violations) {}

    /**
     * @param qualityTotal apart, and never mixed into the security backlog: it blocks nothing
     * @param failing the targets in failure, so there is something to act on from here
     */
    public record DashboardOverview(
            Posture posture,
            Map<String, Long> backlogBySeverity,
            long qualityTotal,
            List<FailingTarget> failing,
            List<DashboardQueryService.RecentScan> recentScans) {}

    @GetMapping
    public DashboardOverview overview(@AuthenticationPrincipal VectispirePrincipal principal) {
        DashboardQueryService.Overview overview =
                dashboard.overview(visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        SecurityOverview.Overview posture = overview.posture();

        return new DashboardOverview(
                new Posture(
                        posture.failingCount(),
                        posture.totalCount(),
                        posture.kevCount(),
                        posture.neverScannedCount(),
                        posture.lastScanFailedCount(),
                        overview.overdueCount()),
                overview.backlogBySeverity(),
                overview.qualityTotal(),
                overview.failing().stream().map(DashboardController::failingOf).toList(),
                overview.recentScans());
    }

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
    public DashboardQueryService.Trends trends(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "90") int days) {

        return dashboard.trends(days, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    @GetMapping("/posture-analytics")
    public PostureTrendAnalytics postureAnalytics(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "30") int days) {

        return dashboard.postureAnalytics(
                days, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
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
                ViolationView.of(posture.verdict().violations()));
    }
}
