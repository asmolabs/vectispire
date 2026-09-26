package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;

/**
 * Reading scans: the history, one scan's detail, and its SBOM — each within an allowance.
 *
 * <p><b>The detail is the scan's findings, not the target's backlog</b>: see the route for why
 * the two must not be conflated.
 */
@Service
public class ScanQueryService {

    private static final int MAX_FINDINGS = 500;
    private static final int MAX_HISTORY = 200;

    private final Scans scans;
    private final Findings findings;
    private final TargetNaming naming;

    public ScanQueryService(Scans scans, Findings findings, TargetNaming naming) {
        this.scans = scans;
        this.findings = findings;
        this.naming = naming;
    }

    public record History(List<ScanView> scans, TargetNaming.Names names) {}

    /** @param findingsTotal how many the scan recorded, which may exceed {@code findings} */
    public record Detail(ScanView scan, TargetNaming.Names names, List<ScanFindingView> findings, long findingsTotal) {

        public boolean findingsTruncated() {
            return findingsTotal > findings.size();
        }
    }

    public History history(Visibility allowed, Long repoId, Long containerId, int limit) {
        TargetNaming.Names names = naming.all();
        // Filtered after the query rather than inside it: the history is capped at two hundred
        // rows, so the cost is a predicate on a short list — and expressing "one of these
        // (kind, id) pairs" in the query would duplicate `IssueFilters`' predicate for a page
        // that cannot grow.
        return new History(
                scans.findHistory(repoId, containerId, Limit.of(Math.clamp(limit, 1, MAX_HISTORY))).stream()
                        .filter(scan -> allowed.permits(scan.target()))
                        .map(ScanView::of)
                        .toList(),
                names);
    }

    public Detail detail(long id, Visibility allowed) {
        ScanEntity scan = visible(id, allowed);
        List<FindingEntity> page = findings.findByScanId(id, Limit.of(MAX_FINDINGS));
        long total = findings.countByScanId(id);
        return new Detail(ScanView.of(scan), naming.all(), page.stream().map(ScanFindingView::of).toList(), total);
    }

    /**
     * The SBOM as the cataloguer wrote it. Absent is a 404 and never an empty document: a scan
     * that failed before the inventory has no SBOM, and an empty one would claim it inventoried
     * nothing.
     */
    public String sbom(long id, Visibility allowed) {
        String document = visible(id, allowed).getSbom();
        if (document == null) {
            throw new NoSuchElementException("This scan produced no SBOM.");
        }
        return document;
    }

    /** The scan, or the same 404 whether it is absent or hidden — see {@link RowVisibility}. */
    private ScanEntity visible(long id, Visibility allowed) {
        return RowVisibility.requireVisibleScan(scans.findById(id).orElse(null), ScanEntity::target, allowed);
    }
}
