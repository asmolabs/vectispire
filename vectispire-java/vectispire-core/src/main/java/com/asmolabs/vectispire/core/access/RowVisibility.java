package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleProject;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

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

    /** The one sentence a refused project gets — absent, hidden, or seen only in part. */
    private static final String PROJECT_NOT_FOUND = "Project not found.";

    /** The one sentence a refused solution gets — absent, or none of it visible. */
    private static final String SOLUTION_NOT_FOUND = "Solution not found.";

    private RowVisibility() {}

    /**
     * The issue, or "Issue not found." for absent and hidden alike.
     *
     * <p><b>Generic, with the target read by the caller's own rule.</b> These guards took {@code
     * IssueEntity}, {@code ScanEntity} and {@code RepositoryEntity}; since each table has a module of
     * its own above {@code access} (decision 0029), {@code access} cannot name them. What stays here is
     * what the class exists for: one sentence per kind of row, for absent and hidden alike.
     */
    public static <T> T requireVisibleIssue(T issue, Function<? super T, ScanTarget> targetOf, Visibility visibility) {
        if (issue == null || !visibility.permits(targetOf.apply(issue))) {
            throw new NotFoundException("Issue not found.");
        }
        return issue;
    }

    /**
     * A scan is visible when its target is.
     *
     * <p><b>One rule rather than one per export.</b> Five routes hand back the same scan under five
     * formats — SBOM, CSAF, CycloneDX, OpenVEX, attestation — and only the first of them checked.
     * Five copies of an authorization rule is five chances for one to be forgotten, and the
     * forgotten one had already happened four times over.
     */
    public static <T> T requireVisibleScan(T scan, Function<? super T, ScanTarget> targetOf, Visibility visibility) {
        // **One message for both cases.** An absent scan said "Scan not found." and a hidden one
        // fell through to "Target not found.": ids are sequential, so the wording alone let a
        // restricted reader enumerate every scan of the deployment. Pass the absent row here as
        // null rather than refusing it beforehand in the caller's own words.
        if (scan == null || !visibility.permits(targetOf.apply(scan))) {
            throw new NotFoundException("Scan not found.");
        }
        return scan;
    }

    /** The same rule for a route named by a repository: absent and hidden read alike. */
    public static <T> T requireVisibleRepository(T repository, long repositoryId, Visibility visibility) {
        if (repository == null || !visibility.permits(new ScanTarget.Repository(repositoryId))) {
            throw new NotFoundException("Repository not found.");
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
            throw new NotFoundException(TARGET_NOT_FOUND);
        }
        return row.get();
    }

    /**
     * A target named by its identifier, refused before anything is read about it.
     *
     * @return the proof a service that may not decide takes in place of the bare target — see {@link
     *     VisibleTarget}, which only this method builds
     */
    public static <T extends ScanTarget> VisibleTarget<T> requireVisible(T target, Visibility visibility) {
        // `null` is left to `permits`, deliberately, and that is not the same as waving it
        // through: an unrestricted caller sees an unclassifiable row, a restricted one does not,
        // which is exactly what the issue guard beside this one already does. Deciding it here
        // instead would have made this stricter than the rule it is meant to reuse — a scan
        // attached to neither target would have 404'd for an administrator too.
        if (!visibility.permits(target)) {
            throw new NotFoundException(TARGET_NOT_FOUND);
        }
        return new VisibleTarget<>(target);
    }

    /**
     * Whether the caller sees an existing project <b>whole</b>, in the sense {@link
     * #requireWhollyVisibleProject} refuses by — the one predicate, so that the solutions tree's {@code
     * checklistsVisible}, which decides whether a screen offers the checklist link, cannot promise a page
     * the guard would then answer with a 404, nor hide one it would open. Images play no part: the
     * checklists speak for the project's repositories (decision 0023, amendment of 2026-09-30).
     *
     * @param repositoryIds every repository filed in the project, visible or not
     */
    public static boolean seesWholeProject(
            long projectId, Collection<Long> repositoryIds, VisibilityService.Allowance allowance) {
        return switch (allowance.visibility()) {
            case Visibility.Everything ignored -> true;
            case Visibility.Only only -> allowance.grantedProjects().contains(projectId)
                    || (!repositoryIds.isEmpty()
                            && repositoryIds.stream().allMatch(id -> only.permits(new ScanTarget.Repository(id))));
        };
    }

    /**
     * A project the caller sees <b>whole</b>, or "Project not found." — for a project that does not
     * exist, one the caller sees nothing of, and one it sees only part of, alike (decision 0032 §8,
     * open question 5).
     *
     * <p><b>Whole</b> means: the caller's visibility is everything; or the project is granted as such
     * — which a key narrowed to a repository never carries ({@link VisibilityService#allowance}); or
     * every one of its repositories is visible <em>and there is at least one</em>. "Every one of none"
     * is the vacuous truth that would hand an empty project granted to nobody to anybody who asked.
     *
     * <p><b>Why a partial reader is refused rather than served less.</b> A project's checklist speaks
     * for every repository in it, and a line's answer or comment names what it found there. Answers
     * without the hidden repositories' figures would still leak through their words; a 404 in the
     * words of an absent project leaks nothing, not even that the project exists.
     *
     * @param name the project's name, empty when there is no such project — passed here rather than
     *     refused by the caller, whose own sentence would tell absent from hidden
     * @param repositoryIds the repositories filed in the project now, as its owner answers them
     * @return the proof a checklist service takes in place of the bare project — only this builds one
     */
    public static VisibleProject requireWhollyVisibleProject(
            long projectId, Optional<String> name, Collection<Long> repositoryIds, VisibilityService.Allowance allowance) {
        if (name.isEmpty() || !seesWholeProject(projectId, repositoryIds, allowance)) {
            throw new NotFoundException(PROJECT_NOT_FOUND);
        }
        return new VisibleProject(projectId, name.get());
    }

    /**
     * A project the caller sees <b>whole, images included</b>, or "Project not found." — the project
     * export's guard (decision 0035 §1), and a report's.
     *
     * <p><b>Stricter than {@link #requireWhollyVisibleProject}.</b> That one reads the repositories alone,
     * because a checklist speaks for them alone (decision 0023, amendment of 2026-09-30). An export carries
     * every target filed in the project — its images' scans, backlog and components too — so a caller who
     * sees every repository and not an image would receive the image's state under the platform's
     * signature. Both conditions hold, or the project is refused in the words of an absent one.
     *
     * @param repositoryIds every repository filed in the project now, visible or not
     * @param filed every target filed in the project now, visible or not, repositories then images
     * @return the scope, never {@code partial}: what the aggregates the export reuses take
     */
    public static VisibleScope requireEveryTargetOfProject(long projectId, Optional<String> name,
            Collection<Long> repositoryIds, Collection<ScanTarget> filed, VisibilityService.Allowance allowance) {
        requireWhollyVisibleProject(projectId, name, repositoryIds, allowance);
        VisibleScope scope = requireVisibleProject(projectId, name, filed, allowance);
        if (scope.partial()) {
            throw new NotFoundException(PROJECT_NOT_FOUND);
        }
        return scope;
    }

    /**
     * A project as far as the caller sees it, or "Project not found." — for a project that does not
     * exist and one the caller sees nothing of, alike. The aggregates over a project (its read, its
     * compliance, its consolidated inventory) take what this returns.
     *
     * <p><b>The solutions tree's rule, and one copy of it.</b> The caller sees the project when its
     * visibility is everything, when it holds the project granted as such — even while the project holds
     * nothing — or when it sees at least one target filed in it. Anything else would let a route answer
     * a project the tree does not show, or refuse one it lists.
     *
     * <p><b>Why a partial reader is served, where the checklists refuse one</b> ({@link
     * #requireWhollyVisibleProject}): a checklist speaks for every repository and its words carry the
     * hidden ones' state; an aggregate here is computed over the visible targets only, every input
     * narrowed, and says {@code partial} — the backlog's and the tree's figures already are.
     *
     * @param name the project's name, empty when there is no such project — passed here rather than
     *     refused by the caller, whose own sentence would tell absent from hidden
     * @param filed every target filed in the project now, visible or not: what {@code partial} is measured
     *     against, and a list narrowed first would read a partial project as whole
     */
    public static VisibleScope requireVisibleProject(
            long projectId, Optional<String> name, Collection<ScanTarget> filed, VisibilityService.Allowance allowance) {
        List<ScanTarget> visible = visibleOf(filed, allowance.visibility());
        if (name.isEmpty() || !(allowance.visibility() instanceof Visibility.Everything
                || allowance.grantedProjects().contains(projectId)
                || !visible.isEmpty())) {
            throw new NotFoundException(PROJECT_NOT_FOUND);
        }
        return new VisibleScope(VisibleScope.Kind.PROJECT, projectId, name.get(), visible, visible.size() < filed.size());
    }

    /**
     * A solution as far as the caller sees it, or "Solution not found." — absent and wholly hidden alike.
     * The tree shows a solution when it shows one of its projects, so the rule is the project's over the
     * solution: everything, one of its projects granted as such, or one target filed under it visible.
     *
     * @param projectIds the solution's projects, for the grants that name one
     * @param filed every target filed in its projects now, visible or not
     */
    public static VisibleScope requireVisibleSolution(
            long solutionId,
            Optional<String> name,
            Collection<Long> projectIds,
            Collection<ScanTarget> filed,
            VisibilityService.Allowance allowance) {
        List<ScanTarget> visible = visibleOf(filed, allowance.visibility());
        if (name.isEmpty() || !(allowance.visibility() instanceof Visibility.Everything
                || projectIds.stream().anyMatch(allowance.grantedProjects()::contains)
                || !visible.isEmpty())) {
            throw new NotFoundException(SOLUTION_NOT_FOUND);
        }
        return new VisibleScope(VisibleScope.Kind.SOLUTION, solutionId, name.get(), visible, visible.size() < filed.size());
    }

    /** The permitted ones, distinct, repositories then images, each ascending — a stable order for a document. */
    private static List<ScanTarget> visibleOf(Collection<ScanTarget> filed, Visibility visibility) {
        return filed.stream()
                .filter(visibility::permits)
                .distinct()
                .sorted(Comparator.comparing((ScanTarget target) -> target instanceof ScanTarget.Container)
                        .thenComparingLong(target -> switch (target) {
                            case ScanTarget.Repository repository -> repository.id();
                            case ScanTarget.Container container -> container.id();
                        }))
                .toList();
    }
}
