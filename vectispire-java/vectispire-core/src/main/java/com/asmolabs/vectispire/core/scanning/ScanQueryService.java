package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.PageRequest;
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

    /** Identifiers per statement: far under every engine's bind-parameter ceiling. */
    private static final int LOOKUP_BATCH = 1_000;

    /** How deep a history read in several statements reaches: {@code offset + limit}, at most. */
    static final int MAX_MERGED_DEPTH = 10_000;

    private final ScanRepository scans;
    private final FindingRepository findings;
    private final TargetNaming naming;

    public ScanQueryService(ScanRepository scans, FindingRepository findings, TargetNaming naming) {
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

    /**
     * The scans the allowance permits, newest first, optionally narrowed to one target: {@code limit} of
     * them — clamped to 1 to 200, as it always was — from the {@code offset}-th.
     *
     * <p><b>The allowance is in the query, and the page cut after it.</b> The history used to be read for the
     * estate, capped, and filtered afterwards: a restricted reader was shown whatever share of the
     * deployment's latest scans happened to be theirs — often none while their own older ones existed — and
     * an offset counted over those rows would have started their next page among scans they may not see. A
     * reader of the estate reads the same rows as before.
     *
     * @param offset scans to skip, zero or a multiple of the clamped limit, or null for none — the clamp
     *     predates paging and a client sending a limit past it has always been answered, so the limit is not
     *     refused where {@link ListWindow} would refuse it; only the offset is
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException an offset the rule refuses
     */
    public History history(Visibility allowed, Long repoId, Long containerId, int limit, Integer offset) {
        ListWindow window = new ListWindow(Math.clamp(limit, 1, MAX_HISTORY), offset == null ? 0 : offset);
        TargetNaming.Names names = naming.all();
        List<ScanEntity> page = switch (allowed) {
            case Visibility.Everything ignored -> scans.findHistoryPage(
                    repoId, containerId, PageRequest.of(window.page(), window.limit()));
            case Visibility.Only only -> within(only, repoId, containerId, window);
        };
        return new History(page.stream().map(ScanView::of).toList(), names);
    }

    /**
     * One page of a restricted reader's history, the allowance bound into the statement.
     *
     * <p><b>In batches of {@link #LOOKUP_BATCH} identifiers</b>: the allowance is sized by the estate, and one
     * bind parameter per target is refused by the PostgreSQL driver past 65,535. One statement — the common
     * case — pages in the database. Several each read their own newest {@code offset + limit}, which hold the
     * union's, and the page is cut from those merged in the query's order: the batches are disjoint, a scan
     * matching through its repository or, naming none, through its image.
     *
     * <p><b>Several statements reach {@link #MAX_MERGED_DEPTH} deep, and no deeper.</b> Each reads its batch's
     * newest {@code offset + limit} whole and the merge holds them all, so a deep offset loaded the history of
     * every batch into the JVM for one page of it — for a reader that sees more than a thousand targets, a single
     * request could hold most of the deployment's scans. Refused past the depth, in words; one statement pages in
     * the database and is not bounded here.
     */
    private List<ScanEntity> within(Visibility.Only only, Long repoId, Long containerId, ListWindow window) {
        List<Long> repositories = only.targets().stream()
                .map(target -> target instanceof ScanTarget.Repository repository ? repository.id() : null)
                .filter(Objects::nonNull).sorted().toList();
        List<Long> images = only.targets().stream()
                .map(target -> target instanceof ScanTarget.Container container ? container.id() : null)
                .filter(Objects::nonNull).sorted().toList();
        int statements = Math.max(batches(repositories.size()), batches(images.size()));
        if (statements == 0) {
            return List.of();
        }
        if (statements == 1) {
            return scans.findHistoryWithin(repoId, containerId, batch(repositories, 0), batch(images, 0),
                    PageRequest.of(window.page(), window.limit()));
        }
        if ((long) window.offset() + window.limit() > MAX_MERGED_DEPTH) {
            throw new InvalidInputException("For a reader of more than " + LOOKUP_BATCH + " targets, the history "
                    + "reaches " + MAX_MERGED_DEPTH + " scans deep: offset plus limit is " + MAX_MERGED_DEPTH + " at most.");
        }
        PageRequest head = PageRequest.of(0, window.offset() + window.limit());
        List<ScanEntity> candidates = new ArrayList<>();
        for (int statement = 0; statement < statements; statement++) {
            candidates.addAll(scans.findHistoryWithin(
                    repoId, containerId, batch(repositories, statement), batch(images, statement), head));
        }
        return window.of(candidates.stream()
                .sorted(Comparator.comparing(ScanEntity::getCreatedAt, Comparator.reverseOrder())
                        .thenComparing(ScanEntity::getId, Comparator.reverseOrder()))
                .toList());
    }

    private static int batches(int size) {
        return (size + LOOKUP_BATCH - 1) / LOOKUP_BATCH;
    }

    /** The {@code index}-th batch, or an identifier no identity column hands out: {@code in ()} is not valid everywhere. */
    private static List<Long> batch(List<Long> ids, int index) {
        int from = index * LOOKUP_BATCH;
        return from < ids.size() ? ids.subList(from, Math.min(from + LOOKUP_BATCH, ids.size())) : List.of(-1L);
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
            throw new NotFoundException("This scan produced no SBOM.");
        }
        return document;
    }

    /** The scan, or the same 404 whether it is absent or hidden — see {@link RowVisibility}. */
    private ScanEntity visible(long id, Visibility allowed) {
        return RowVisibility.requireVisibleScan(scans.findById(id).orElse(null), ScanEntity::target, allowed);
    }
}
