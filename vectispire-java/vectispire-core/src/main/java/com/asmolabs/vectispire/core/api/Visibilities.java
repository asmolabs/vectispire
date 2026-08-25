package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
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

    /**
     * A scan is visible when its target is.
     *
     * <p><b>Here rather than copied into each controller that exports one.</b> Five routes hand
     * back the same scan under five formats — SBOM, CSAF, CycloneDX, OpenVEX, attestation — and
     * only the first of them checked. Five copies of an authorization rule is five chances for
     * one to be forgotten, and the forgotten one had already happened four times over.
     */
    static void requireVisible(ScanEntity scan, Visibility visibility) {
        if (scan == null) {
            throw new NoSuchElementException("Scan not found.");
        }
        requireVisible(targetOf(scan), visibility);
    }

    /** A scan attached to neither is unclassifiable, and treated as invisible. */
    static ScanTarget targetOf(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return new ScanTarget.Repository(scan.getRepoId());
        }
        return scan.getContainerId() == null ? null : new ScanTarget.Container(scan.getContainerId());
    }

    static void requireVisible(ScanTarget target, Visibility visibility) {
        // `null` is left to `permits`, deliberately, and that is not the same as waving it
        // through: an unrestricted caller sees an unclassifiable row, a restricted one does not,
        // which is exactly what the issue guard beside this one already does. Deciding it here
        // instead would have made this stricter than the rule it is meant to reuse — a scan
        // attached to neither target would have 404'd for an administrator too.
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
