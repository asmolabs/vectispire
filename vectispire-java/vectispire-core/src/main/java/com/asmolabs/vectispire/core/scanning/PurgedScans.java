package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.Collection;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The scans a purge takes: every one of a deleted target, or every one whose target is gone.
 *
 * <p>One answer for every module purging what hangs off a scan — components, AI reviews, findings —
 * so that two listeners of the same purge cannot disagree about which scans it concerns. It was a
 * default method of {@code ScanRepository}; {@code TargetPurge} belongs to {@code targets}'
 * API now, which a repository sits below, and the listeners in other modules could not have reached
 * the repository anyway (decision 0029). The queries are the repository's, unchanged, and run in the
 * deleting transaction every caller is in.
 */
@Service
public class PurgedScans {

    private final ScanRepository scans;
    private final FindingRepository findings;

    public PurgedScans(ScanRepository scans, FindingRepository findings) {
        this.scans = scans;
        this.findings = findings;
    }

    /**
     * Hands every scan a purge takes to {@code action}, a thousand identifiers at a time, and answers
     * how many there were.
     *
     * <p><b>In batches, because a target's scans are sized by its history.</b> Every listener deleted
     * them in one statement, {@code in} with a bind parameter per identifier, which the PostgreSQL driver
     * refuses past 65,535 — and the orphans' cleanup takes every deleted target's at once. The batches
     * run in the purging transaction, one after the other; nothing about the phases changes.
     */
    public int inBatches(TargetPurge purge, java.util.function.Consumer<List<Long>> action) {
        List<Long> ids = idsOf(purge);
        for (int from = 0; from < ids.size(); from += PURGE_BATCH) {
            action.accept(ids.subList(from, Math.min(from + PURGE_BATCH, ids.size())));
        }
        return ids.size();
    }

    /** Identifiers per deleting statement: far under every engine's bind-parameter ceiling. */
    static final int PURGE_BATCH = 1_000;

    private List<Long> idsOf(TargetPurge purge) {
        return switch (purge) {
            case TargetDeleted deleted -> switch (deleted.target()) {
                case ScanTarget.Repository repository -> scans.findIdsByRepoId(repository.id());
                case ScanTarget.Container container -> scans.findIdsByContainerId(container.id());
            };
            case OrphanedTargetRows ignored -> scans.findOrphanedIds();
        };
    }

    /**
     * The findings that are occurrences of these issues, deleted — for the backlog's purge listener,
     * in the findings phase. A finding hangs off both a scan and an issue; {@code scanning}'s own
     * listener takes them by scan, and {@code issues}' asks here to take them by issue, since the
     * issues are its to select and the findings this module's to delete (decision 0029).
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void deleteFindingsOfIssues(Collection<Long> issueIds) {
        findings.deleteByIssueIdIn(issueIds);
    }
}
