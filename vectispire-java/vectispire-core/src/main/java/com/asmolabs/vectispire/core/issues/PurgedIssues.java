package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.persistence.Issues;
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
 * It was a default method of the {@code Issues} repository, for the reason {@code PurgedScans} gives
 * (decision 0029); the queries are unchanged.
 */
@Service
public class PurgedIssues {

    private final Issues issues;

    public PurgedIssues(Issues issues) {
        this.issues = issues;
    }

    public List<Long> idsOf(TargetPurge purge) {
        return switch (purge) {
            case TargetDeleted deleted -> switch (deleted.target()) {
                case ScanTarget.Repository repository -> issues.findIdsByRepoId(repository.id());
                case ScanTarget.Container container -> issues.findIdsByContainerId(container.id());
            };
            case OrphanedTargetRows ignored -> issues.findOrphanedIds();
        };
    }
}
