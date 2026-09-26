package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.List;
import org.springframework.stereotype.Service;

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

    public PurgedScans(Scans scans) {
        this.scans = scans;
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
}
