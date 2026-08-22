package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.gate.GateVerdict;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
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
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Limit;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
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

    private final GateService gate;
    private final Issues issues;
    private final Scans scans;
    private final TargetNaming naming;

    private final VisibilityService visibility;
    private final SlaService sla;

    public DashboardController(
            GateService gate,
            Issues issues,
            Scans scans,
            TargetNaming naming,
            VisibilityService visibility,
            SlaService sla) {
        this.gate = gate;
        this.issues = issues;
        this.scans = scans;
        this.naming = naming;
        this.visibility = visibility;
        this.sla = sla;
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
