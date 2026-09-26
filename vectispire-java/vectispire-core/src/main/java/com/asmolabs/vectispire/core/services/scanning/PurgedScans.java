package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Scans;
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
 * default method of the {@code Scans} repository; {@code TargetPurge} belongs to {@code targets}'
 * API now, which a repository sits below, and the listeners in other modules could not have reached
 * the repository anyway (decision 0029). The queries are the repository's, unchanged, and run in the
 * deleting transaction every caller is in.
 */
@Service
public class PurgedScans {

    private final Scans scans;
    private final Findings findings;

    public PurgedScans(Scans scans, Findings findings) {
        this.scans = scans;
        this.findings = findings;
    }

    public List<Long> idsOf(TargetPurge purge) {
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
