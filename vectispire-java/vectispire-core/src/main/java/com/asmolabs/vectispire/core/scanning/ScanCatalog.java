package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.scanning.persistence.FindingGraphQueries;
import com.asmolabs.vectispire.core.scanning.persistence.Findings;
import com.asmolabs.vectispire.core.scanning.persistence.Scans;
import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import com.asmolabs.vectispire.core.scanning.persistence.queries.PackageImpact;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The scans and their findings as the other modules read them: views and query records, never rows.
 *
 * <p><b>Each method is a query that module ran on the repository itself</b> — the agents' queue
 * figures, the dashboard's recent scans, the exports' document for one scan, the licence and SBOM
 * screens, the compliance evidence, the gate's latest scans. Same query, same parameters, same order;
 * the answer is the {@link ScanView} and {@link ScanFindingView} the scan routes already return,
 * whose components are the entities' property names, so a reader changed {@code getStatus()} for
 * {@code status()} and nothing else (decision 0029). The two projections the queries select into and
 * several readers share — {@link LatestScanRow} and {@link PackageImpact} — are
 * published as they are, read-only.
 *
 * <p>Row arrays do not cross: a grouped count answers a map, a pair of target columns a {@link
 * ScanOfTarget}.
 */
@Service
@Transactional(readOnly = true)
public class ScanCatalog {

    private final Scans scans;
    private final Findings findings;

    public ScanCatalog(Scans scans, Findings findings) {
        this.scans = scans;
        this.findings = findings;
    }

    /** A scan and the target it is of, without the rest of the row. */
    public record ScanOfTarget(long id, Long repoId, Long containerId) {

        /** A scan attached to neither target is unclassifiable, and left to {@link Visibility#permits}. */
        public ScanTarget target() {
            if (repoId != null) {
                return new ScanTarget.Repository(repoId);
            }
            return containerId == null ? null : new ScanTarget.Container(containerId);
        }
    }

    /** A finding, with the scan it was observed in — what the blast radius walks. */
    public record FindingOnScan(ScanFindingView finding, ScanView scan) {}

    // ------------------------------------------------------------------ scans

    public Optional<ScanView> scan(long id) {
        return scans.findById(id).map(ScanView::of);
    }

    /** Every scan, in the table's order. */
    public List<ScanView> all() {
        return scans.findAll().stream().map(ScanView::of).toList();
    }

    public List<ScanView> ofRepository(long repoId) {
        return scans.findByRepoId(repoId).stream().map(ScanView::of).toList();
    }

    public List<ScanView> ofContainer(long containerId) {
        return scans.findByContainerId(containerId).stream().map(ScanView::of).toList();
    }

    /** Newest first; both targets {@code null} for the whole deployment's. */
    public List<ScanView> history(Long repoId, Long containerId, int limit) {
        return scans.findHistory(repoId, containerId, Limit.of(limit)).stream().map(ScanView::of).toList();
    }

    /** Newest first, of the targets named; each collection must hold at least one value. */
    public List<ScanView> recentWithin(Collection<Long> repoIds, Collection<Long> containerIds, int limit) {
        return scans.findRecentWithin(repoIds, containerIds, Limit.of(limit)).stream().map(ScanView::of).toList();
    }

    /** The identifiers of a target's most recent scans, newest first. */
    public List<Long> recentIds(ScanTarget target, int limit) {
        return switch (target) {
            case ScanTarget.Repository repository -> scans.findRecentIdsByRepoId(repository.id(), Limit.of(limit));
            case ScanTarget.Container container -> scans.findRecentIdsByContainerId(container.id(), Limit.of(limit));
        };
    }

    /** Scans holding an SBOM that the components inventory has not indexed yet, newest first. */
    public List<ScanView> withSbomButNoComponents(int limit) {
        return scans.findWithSbomButNoComponents(Limit.of(limit)).stream().map(ScanView::of).toList();
    }

    public List<LatestScanRow> latestPerRepository() {
        return scans.findLatestPerRepository();
    }

    public List<LatestScanRow> latestPerContainer() {
        return scans.findLatestPerContainer();
    }

    /** Scans with this status, newest first, as identifier and target only. */
    public List<ScanOfTarget> withStatusNewestFirst(String status) {
        return scans.idsAndTargetsNewestFirst(status).stream()
                .map(row -> new ScanOfTarget(((Number) row[0]).longValue(), asLong(row[1]), asLong(row[2])))
                .toList();
    }

    /** The distinct targets holding a scan with this status, as repository and container columns. */
    public List<ScanOfTarget> targetsWithStatus(String status) {
        return scans.targetsWithStatus(status).stream()
                .map(row -> new ScanOfTarget(0L, asLong(row[0]), asLong(row[1])))
                .toList();
    }

    /** Whether the target holds a scan with this status, ignoring case. */
    public boolean hasScanWithStatus(ScanTarget target, String status) {
        return switch (target) {
            case ScanTarget.Repository repository -> scans.existsByRepoIdAndStatusIgnoreCase(repository.id(), status);
            case ScanTarget.Container container -> scans.existsByContainerIdAndStatusIgnoreCase(container.id(), status);
        };
    }

    /** The target's first scan with this status created after {@code after}, oldest first. */
    public Optional<ScanView> nextWithStatusAfter(ScanTarget target, String status, Instant after) {
        return (switch (target) {
            case ScanTarget.Repository repository ->
                    scans.findFirstByRepoIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(repository.id(), status, after);
            case ScanTarget.Container container ->
                    scans.findFirstByContainerIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(container.id(), status, after);
        }).map(ScanView::of);
    }

    // ------------------------------------------------------------------ the queue's figures

    /** Scans with any of these statuses, oldest first. */
    public List<ScanView> withStatusOldestFirst(Collection<String> statuses) {
        return scans.findByStatusInOrderByCreatedAtAsc(statuses).stream().map(ScanView::of).toList();
    }

    public long countWithStatusSince(String status, Instant after) {
        return scans.countByStatusAndCreatedAtAfter(status, after);
    }

    /** Null when no such scan recorded a duration. */
    public Double averageDurationMsSince(String status, Instant after) {
        return scans.findAvgDurationMsByStatusAndCreatedAtAfter(status, after);
    }

    public long countWithStatusClaimedBy(String status, String claimant) {
        return scans.countByStatusAndClaimedBy(status, claimant);
    }

    /** Scans with this status per required label — the label {@code null} when none is — in query order. */
    public Map<String, Long> countByRequiredLabel(String status) {
        return grouped(scans.countPendingByRequiredLabel(status));
    }

    /** Scans with this status per claimant, in query order. */
    public Map<String, Long> countByClaimant(String status) {
        return grouped(scans.countRunningByClaimant(status));
    }

    // ------------------------------------------------------------------ findings

    public List<ScanFindingView> findings(long scanId) {
        return findings.findByScanId(scanId).stream().map(ScanFindingView::of).toList();
    }

    /** The licence findings of these scans. */
    public List<ScanFindingView> licenseFindings(Collection<Long> scanIds) {
        return findings.findLicenseFindings(scanIds).stream().map(ScanFindingView::of).toList();
    }

    public long countFindings(long scanId, String severity) {
        return findings.countByScanIdAndSeverity(scanId, severity);
    }

    public long countKevFindings(long scanId) {
        return findings.countByScanIdAndIsKevTrue(scanId);
    }

    public long countFindingsOfType(long scanId, String type) {
        return findings.countByScanIdAndType(scanId, type);
    }

    /** See {@link FindingGraphQueries#forGraph}: narrowed by visibility in the query itself. */
    public List<FindingOnScan> findingsForGraph(String query, boolean cveQuery, boolean excludeSecrets, Visibility allowed) {
        return findings.forGraph(query, cveQuery, excludeSecrets, allowed).stream()
                .map(row -> new FindingOnScan(ScanFindingView.of(row.finding()), ScanView.of(row.scan())))
                .toList();
    }

    /** See {@link FindingGraphQueries#packageImpacts}. */
    public List<PackageImpact> packageImpacts(Visibility allowed) {
        return findings.packageImpacts(allowed);
    }

    private static Map<String, Long> grouped(List<Object[]> rows) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Object[] row : rows) {
            counts.put((String) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    private static Long asLong(Object value) {
        return value == null ? null : ((Number) value).longValue();
    }
}
