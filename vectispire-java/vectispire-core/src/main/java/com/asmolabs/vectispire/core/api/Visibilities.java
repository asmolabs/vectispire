package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * The guard for a route that reaches a row by its identifier.
 *
 * <p><b>404, never 403.</b> A 403 says "this exists and is not yours", which answers the
 * question the caller was probing with — whether repository 7 exists at all. Since the whole
 * point of restricting visibility is that a reader cannot enumerate what they were not given,
 * a refusal has to be indistinguishable from an absence.
 *
 * <p>Also 404 for a row that genuinely is not there, so the two cases cost the same and no
 * timing or wording tells them apart.
 */
final class Visibilities {

    private Visibilities() {}

    static void requireVisible(IssueEntity issue, Visibility visibility) {
        if (issue == null || !visibility.permits(targetOf(issue))) {
            throw new NoSuchElementException("Issue not found.");
        }
    }

    static void requireVisible(ScanTarget target, Visibility visibility) {
        if (!visibility.permits(target)) {
            throw new NoSuchElementException("Target not found.");
        }
    }

    /**
     * A row attached to neither a repository nor a container.
     *
     * <p>Impossible through any code path, and treated as invisible rather than as visible: an
     * unclassifiable row is exactly the kind of thing a restriction should not wave through.
     */
    private static ScanTarget targetOf(IssueEntity issue) {
        return Optional.<ScanTarget>ofNullable(
                        issue.getRepoId() != null ? new ScanTarget.Repository(issue.getRepoId()) : null)
                .or(() -> Optional.ofNullable(
                        issue.getContainerId() != null ? new ScanTarget.Container(issue.getContainerId()) : null))
                .orElse(null);
    }
}
