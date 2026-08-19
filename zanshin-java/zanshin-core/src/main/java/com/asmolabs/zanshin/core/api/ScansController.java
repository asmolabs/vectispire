package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.services.TargetNaming;
import com.asmolabs.zanshin.core.services.VisibilityService;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.data.domain.Limit;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The scan history, and each scan's detail.
 *
 * <p><b>The detail shows the scan's findings, not the target's backlog.</b> The two differ: the
 * backlog carries history — an issue seen three scans ago and still open belongs to it — while
 * a scan reports only what it observed that day. Conflating them would suggest a scan "found"
 * an issue it merely saw again.
 */
@RestController
@RequestMapping("/api/v1/scans")
@RequiresAccount
public class ScansController {

    private static final int MAX_FINDINGS = 500;
    private static final int MAX_HISTORY = 200;

    private final Scans scans;
    private final Findings findings;
    private final TargetNaming naming;

    private final VisibilityService visibility;

    public ScansController(
            Scans scans, Findings findings, TargetNaming naming, VisibilityService visibility) {
        this.scans = scans;
        this.findings = findings;
        this.naming = naming;
        this.visibility = visibility;
    }

    public record Summary(
            Long id,
            String status,
            String branch,
            Instant createdAt,
            Long durationMs,
            int findingsCount,
            int newIssuesCount,
            int resolvedIssuesCount,
            String error,
            String claimedBy,
            int attempts,
            String targetKind,
            Long targetId,
            String targetName) {}

    public record FindingView(
            Long id,
            String type,
            String severity,
            String identifier,
            String packageName,
            String packageVersion,
            String fixVersions,
            String filePath,
            Integer line,
            String description,
            String link) {}

    /** @param findingsTruncated said explicitly, or a scan of a thousand findings would show five hundred in silence */
    public record Detail(
            Summary scan,
            String subPath,
            boolean hasSbom,
            List<FindingView> findings,
            long findingsTotal,
            boolean findingsTruncated) {}

    @GetMapping
    public List<Summary> list(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId,
            @RequestParam(required = false, defaultValue = "50") int limit) {

        TargetNaming.Names names = naming.all();
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        // Filtered after the query rather than inside it: the history is capped at two hundred
        // rows, so the cost is a predicate on a short list — and expressing "one of these
        // (kind, id) pairs" in the query would duplicate `IssueFilters`' predicate for a page
        // that cannot grow.
        return scans.findHistory(repoId, containerId, Limit.of(Math.clamp(limit, 1, MAX_HISTORY))).stream()
                .filter(scan -> allowed.permits(targetOf(scan)))
                .map(scan -> summaryOf(scan, names))
                .toList();
    }

    @GetMapping("/{id}")
    public Detail detail(@AuthenticationPrincipal ZanshinPrincipal principal, @PathVariable long id) {
        ScanEntity scan = scans.findById(id).orElseThrow(() -> new NoSuchElementException("Scan not found."));
        Visibilities.requireVisible(
                targetOf(scan), visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        List<FindingEntity> page = findings.findByScanId(id, Limit.of(MAX_FINDINGS));
        long total = findings.countByScanId(id);

        return new Detail(
                summaryOf(scan, naming.all()),
                scan.getSubPath(),
                // The SBOM is not returned here: it weighs megabytes and the screen shows none
                // of it. Its export has its own route.
                scan.getSbom() != null,
                page.stream().map(ScansController::viewOf).toList(),
                total,
                total > page.size());
    }

    /** A scan with neither target is invisible rather than visible: see {@code Visibilities}. */
    private static ScanTarget targetOf(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return new ScanTarget.Repository(scan.getRepoId());
        }
        return scan.getContainerId() == null ? null : new ScanTarget.Container(scan.getContainerId());
    }

    private static Summary summaryOf(ScanEntity scan, TargetNaming.Names names) {
        return new Summary(
                scan.getId(),
                scan.getStatus(),
                scan.getBranch(),
                scan.getCreatedAt(),
                scan.getDurationMs(),
                scan.getFindingsCount(),
                scan.getNewIssuesCount(),
                scan.getResolvedIssuesCount(),
                scan.getError(),
                scan.getClaimedBy(),
                scan.getAttempts(),
                scan.getRepoId() != null ? "repository" : "container",
                scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId(),
                names.of(scan.getRepoId(), scan.getContainerId()));
    }

    private static FindingView viewOf(FindingEntity finding) {
        return new FindingView(
                finding.getId(),
                finding.getType(),
                finding.getSeverity(),
                finding.getIdentifier(),
                finding.getPackageName(),
                finding.getPackageVersion(),
                finding.getFixVersions(),
                finding.getFilePath(),
                finding.getLine(),
                finding.getDescription(),
                finding.getLink());
    }
}
