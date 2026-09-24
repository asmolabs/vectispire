package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import java.util.NoSuchElementException;

/**
 * The issue and repository halves of {@code api.Visibilities}, for the services the routes that
 * used them now delegate to.
 *
 * <p><b>A copy, and it has to stay one word for word.</b> {@code Visibilities} is package-private
 * to {@code api}, and a service cannot reach upwards into it; the lookups those routes did moved
 * into services, so the refusal had to move with them or the check would happen after the read it
 * guards. The two must answer identically — same rule, same message — because the message is what
 * a restricted reader compares: "Issue not found." for an absent id and for a hidden one alike, or
 * the wording becomes an oracle for which sequential ids exist. Change one, change both.
 */
final class RowVisibility {

    private RowVisibility() {}

    /** 404 for absent and hidden alike: the absent row comes here as null, never refused first. */
    static IssueEntity requireVisible(IssueEntity issue, Visibility visibility) {
        if (issue == null || !isVisible(issue, visibility)) {
            throw new NoSuchElementException("Issue not found.");
        }
        return issue;
    }

    /**
     * The same rule for a lookup that has no single row to refuse — a search by CVE across every
     * target, where the rows the caller may not see have to be dropped before anything is read.
     */
    static boolean isVisible(IssueEntity issue, Visibility visibility) {
        return visibility.permits(targetOf(issue));
    }

    static RepositoryEntity requireVisible(RepositoryEntity repository, Visibility visibility) {
        if (repository == null || !visibility.permits(new ScanTarget.Repository(repository.getId()))) {
            throw new NoSuchElementException("Repository not found.");
        }
        return repository;
    }

    /**
     * An issue attached to neither target is unclassifiable, and left to {@code permits}: an
     * unrestricted caller sees it, a restricted one does not — exactly what {@code Visibilities}
     * answers.
     */
    private static ScanTarget targetOf(IssueEntity issue) {
        if (issue.getRepoId() != null) {
            return new ScanTarget.Repository(issue.getRepoId());
        }
        return issue.getContainerId() == null ? null : new ScanTarget.Container(issue.getContainerId());
    }
}
