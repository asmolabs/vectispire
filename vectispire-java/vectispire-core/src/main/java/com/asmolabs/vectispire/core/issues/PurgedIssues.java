package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The issues a purge takes: every one of a deleted target, or every one whose target is gone.
 *
 * <p>One answer for every module purging what hangs off an issue — ticket links, triage events,
 * findings — so that two listeners of the same purge cannot disagree about which issues it concerns.
 * It was a default method of {@code IssueRepository}, for the reason {@code PurgedScans} gives
 * (decision 0029); the queries are unchanged.
 */
@Service
public class PurgedIssues {

    private final IssueRepository issues;

    public PurgedIssues(IssueRepository issues) {
        this.issues = issues;
    }

    /**
     * Hands every issue a purge takes to {@code action}, a thousand identifiers at a time, and answers
     * how many there were.
     *
     * <p><b>In batches, because a target's issues are sized by its history.</b> Every listener deleted
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
                case ScanTarget.Repository repository -> issues.findIdsByRepoId(repository.id());
                case ScanTarget.Container container -> issues.findIdsByContainerId(container.id());
            };
            case OrphanedTargetRows ignored -> issues.findOrphanedIds();
        };
    }
}
