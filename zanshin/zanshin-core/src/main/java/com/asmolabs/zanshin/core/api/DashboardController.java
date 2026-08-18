package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.gate.GateVerdict;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.asmolabs.zanshin.core.services.GateService;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Limit;
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

    public DashboardController(GateService gate, Issues issues, Scans scans) {
        this.gate = gate;
        this.issues = issues;
        this.scans = scans;
    }

    /**
     * @param neverScannedCount a target nobody has scanned passes every policy: its lack of
     *     findings is not a lack of problems. Its own figure, therefore
     */
    public record Posture(
            int failingCount,
            int totalCount,
            long kevCount,
            long neverScannedCount,
            long lastScanFailedCount) {}

    public record FailingTarget(
            String kind, Long targetId, String name, boolean observed, List<GateVerdict.Violation> violations) {}

    public record RecentScan(
            Long id, Long repoId, Long containerId, String status, int findingsCount, String error, Instant createdAt) {}

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
    public Overview overview() {
        SecurityOverview.Overview posture = gate.overview();

        return new Overview(
                new Posture(
                        posture.failingCount(),
                        posture.totalCount(),
                        posture.kevCount(),
                        posture.neverScannedCount(),
                        posture.lastScanFailedCount()),
                backlogBySeverity(),
                issues.countByStateAndType(IssueState.OPEN.wireName(), FindingType.QUALITY.wireName()),
                posture.targets().stream()
                        .filter(target -> !target.passed())
                        .map(DashboardController::failingOf)
                        .toList(),
                recentScans());
    }

    private Map<String, Long> backlogBySeverity() {
        Map<String, Long> counts = new HashMap<>();
        for (Object[] row : issues.countOpenBySeverity(IssueState.OPEN.wireName())) {
            counts.put((String) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    private List<RecentScan> recentScans() {
        return scans.findHistory(null, null, Limit.of(RECENT_SCANS)).stream()
                .map(DashboardController::recentOf)
                .toList();
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

    private static RecentScan recentOf(ScanEntity scan) {
        return new RecentScan(
                scan.getId(),
                scan.getRepoId(),
                scan.getContainerId(),
                scan.getStatus(),
                scan.getFindingsCount(),
                scan.getError(),
                scan.getCreatedAt());
    }
}
