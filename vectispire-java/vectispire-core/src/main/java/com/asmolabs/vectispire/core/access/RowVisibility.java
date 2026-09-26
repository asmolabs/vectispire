package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import java.util.NoSuchElementException;

/**
 * The guard for a read that reaches a row by its identifier — the one copy of it.
 *
 * <p><b>404, never 403.</b> A 403 says "this exists and is not yours", which answers the
 * question the caller was probing with — whether repository 7 exists at all. Since the whole
 * point of restricting visibility is that a reader cannot enumerate what they were not given,
 * a refusal has to be indistinguishable from an absence.
 *
 * <p>Also 404 for a row that genuinely is not there, so the two cases cost the same and no
 * timing or wording tells them apart. <b>The absent row comes here as null</b>, never refused by
 * the caller first: nine routes did, each in its own words, and each wording was an oracle.
 *
 * <p><b>Here, public, and nowhere else.</b> It lived in {@code api.Visibilities}, package-private;
 * when the lookups moved into services the refusal had to move with them, or the check would run
 * after the read it guards — and it was copied, into this class, into {@code TicketLinkService}
 * and into {@code ScanQueryService}, each copy promising in a comment to stay word for word the
 * same. {@code api.Visibilities} now delegates here, so a route and a service refuse with one
 * sentence because there is one sentence.
 */
public final class RowVisibility {

    /** The one sentence a refused target gets, whether it is absent or hidden. */
    private static final String TARGET_NOT_FOUND = "Target not found.";

    private RowVisibility() {}

    /** The issue, or "Issue not found." for absent and hidden alike. */
    public static IssueEntity requireVisible(IssueEntity issue, Visibility visibility) {
        if (issue == null || !isVisible(issue, visibility)) {
            throw new NoSuchElementException("Issue not found.");
        }
        return issue;
    }

    /**
     * The same rule, for a route that looks issues up by something other than their id.
     *
     * <p><b>A lookup by CVE is a search across every target</b>, so it has no single row to refuse:
     * the rows the caller may not see have to be dropped before anything is read from them. The
     * explanation route took the first match from anywhere in the estate — package, version, fix,
     * EPSS — and its answer differed depending on whether a match existed, which told a reader
     * with one repository whether a CVE was present in repositories they were never given.
     */
    public static boolean isVisible(IssueEntity issue, Visibility visibility) {
        return visibility.permits(targetOf(issue));
    }

    /**
     * A scan is visible when its target is.
     *
     * <p><b>One rule rather than one per export.</b> Five routes hand back the same scan under five
     * formats — SBOM, CSAF, CycloneDX, OpenVEX, attestation — and only the first of them checked.
     * Five copies of an authorization rule is five chances for one to be forgotten, and the
     * forgotten one had already happened four times over.
     */
    public static ScanEntity requireVisible(ScanEntity scan, Visibility visibility) {
        // **One message for both cases.** An absent scan said "Scan not found." and a hidden one
        // fell through to "Target not found.": ids are sequential, so the wording alone let a
        // restricted reader enumerate every scan of the deployment. Pass the absent row here as
        // null rather than refusing it beforehand in the caller's own words.
        if (scan == null || !visibility.permits(targetOf(scan))) {
            throw new NoSuchElementException("Scan not found.");
        }
        return scan;
    }

    /** The same rule for a route named by a repository: absent and hidden read alike. */
    public static RepositoryEntity requireVisible(RepositoryEntity repository, Visibility visibility) {
        if (repository == null || !visibility.permits(new ScanTarget.Repository(repository.getId()))) {
            throw new NoSuchElementException("Repository not found.");
        }
        return repository;
    }

    /**
     * A target's row, or "Target not found." for absent and hidden alike.
     *
     * <p><b>For a write that loads the row itself.</b> The update routes looked the row up first
     * and refused an absent one in their own words — "No repository with id 7." — then refused a
     * hidden one with this class's. Two sentences for one refusal is the oracle the class exists to
     * remove: whoever gets the second has learned the row exists.
     */
    public static <T> T requireVisible(java.util.Optional<T> row, ScanTarget target, Visibility visibility) {
        if (row.isEmpty() || !visibility.permits(target)) {
            throw new NoSuchElementException(TARGET_NOT_FOUND);
        }
        return row.get();
    }

    /** A target named by its identifier, refused before anything is read about it. */
    public static void requireVisible(ScanTarget target, Visibility visibility) {
        // `null` is left to `permits`, deliberately, and that is not the same as waving it
        // through: an unrestricted caller sees an unclassifiable row, a restricted one does not,
        // which is exactly what the issue guard beside this one already does. Deciding it here
        // instead would have made this stricter than the rule it is meant to reuse — a scan
        // attached to neither target would have 404'd for an administrator too.
        if (!visibility.permits(target)) {
            throw new NoSuchElementException(TARGET_NOT_FOUND);
        }
    }

    /**
     * A scan attached to neither target is unclassifiable, and left to {@link Visibility#permits}:
     * visible to an unrestricted caller, hidden from a restricted one.
     */
    public static ScanTarget targetOf(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return new ScanTarget.Repository(scan.getRepoId());
        }
        return scan.getContainerId() == null ? null : new ScanTarget.Container(scan.getContainerId());
    }

    /** The same reading for an issue: a row attached to neither target is left to {@code permits}. */
    public static ScanTarget targetOf(IssueEntity issue) {
        if (issue.getRepoId() != null) {
            return new ScanTarget.Repository(issue.getRepoId());
        }
        return issue.getContainerId() == null ? null : new ScanTarget.Container(issue.getContainerId());
    }
}
