package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Projects;
import com.asmolabs.vectispire.core.repositories.Solutions;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.shared.RowVisibility;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.time.Clock;
import java.time.Instant;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Solutions, their projects, and which project a repository is filed in (decision 0023).
 *
 * <p><b>One service for both levels, and the read elsewhere.</b> The writes share their invariants
 * — a solution is deleted only when it holds no project, a project's name is unique within its
 * solution, a repository is in at most one project — and splitting solutions from projects would
 * put each half of those rules in a different class. The tree is {@link SolutionQueryService}'s,
 * because it is decided by the reader's visibility and computes figures, which no write here does.
 *
 * <p><b>Filing a repository is an access change.</b> A project grant resolves at each request
 * into the project's repositories, so a move changes what the project's grantees see at once, in
 * both directions, with no grant row touched. That is the whole point of the decision and also its
 * sharpest edge, so every move is audited in words that say it.
 *
 * <p>Refusals follow the house convention: {@link IllegalArgumentException} for what the
 * administrator can correct (400), {@link NoSuchElementException} for what is not there or not
 * visible (404, in one sentence for both), {@link SolutionNotEmptyException} for a deletion the
 * current state forbids (409).
 */
@Service
public class SolutionAdministrationService {

    /** The width of {@code t_solution.name} and {@code t_project.name}. */
    static final int NAME_LENGTH = 100;

    /** The width of both {@code description} columns. */
    static final int DESCRIPTION_LENGTH = 255;

    private final Solutions solutions;
    private final Projects projects;
    private final GitRepositories repositories;
    private final UserTargets userTargets;
    private final TeamTargets teamTargets;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public SolutionAdministrationService(
            Solutions solutions,
            Projects projects,
            GitRepositories repositories,
            UserTargets userTargets,
            TeamTargets teamTargets,
            AuditLogService audit,
            TransactionTemplate transactions,
            Clock clock) {
        this.solutions = solutions;
        this.projects = projects;
        this.repositories = repositories;
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** A solution as the routes return it: the entity's properties, and nothing else. */
    public record SolutionView(Long id, String name, String description, Instant createdAt) {

        static SolutionView of(SolutionEntity solution) {
            return new SolutionView(solution.getId(), solution.getName(), solution.getDescription(), solution.getCreatedAt());
        }
    }

    /** A project as the routes return it: the entity's properties, and nothing else. */
    public record ProjectView(Long id, Long solutionId, String name, String description, Instant createdAt) {

        static ProjectView of(ProjectEntity project) {
            return new ProjectView(
                    project.getId(), project.getSolutionId(), project.getName(), project.getDescription(), project.getCreatedAt());
        }
    }

    /** A solution still holding projects: deleting it would orphan them, so it is refused (409). */
    public static final class SolutionNotEmptyException extends RuntimeException {

        SolutionNotEmptyException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------------------ solutions

    public SolutionView createSolution(String requestedName, String description, RequestActor actor) {
        String name = BoundedText.required(requestedName, NAME_LENGTH, "A solution name");
        refuseIfSolutionNameTaken(name, null);

        SolutionEntity solution = new SolutionEntity();
        solution.setName(name);
        solution.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        solution.setCreatedAt(clock.instant());
        SolutionEntity saved = solutions.save(solution);

        audit.record(actor.entry(AuditOperation.SOLUTION_UPDATED, String.valueOf(saved.getId()), "Solution created: " + name));
        return SolutionView.of(saved);
    }

    /** Either field may be null, which leaves it as it is; an empty description clears it. */
    public SolutionView updateSolution(long id, String requestedName, String description, RequestActor actor) {
        SolutionEntity solution = requireSolution(id);
        String previous = solution.getName();

        if (requestedName != null) {
            String name = BoundedText.required(requestedName, NAME_LENGTH, "A solution name");
            refuseIfSolutionNameTaken(name, id);
            solution.setName(name);
        }
        if (description != null) {
            solution.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        }
        SolutionEntity saved = solutions.save(solution);

        audit.record(actor.entry(AuditOperation.SOLUTION_UPDATED, String.valueOf(id),
                "Solution " + previous + " updated" + (previous.equals(saved.getName()) ? "" : " → " + saved.getName())));
        return SolutionView.of(saved);
    }

    /**
     * Deletes an empty solution.
     *
     * <p><b>Refused while it holds a project</b>, rather than taking its projects with it: a
     * project carries grants and a filing of repositories, and a solution deleted in one click
     * would revoke the first and scatter the second without anybody having looked at either. The
     * administrator deletes or moves the projects first, one audited gesture each.
     */
    public void deleteSolution(long id, RequestActor actor) {
        SolutionEntity solution = requireSolution(id);
        long held = projects.countBySolutionId(id);
        if (held > 0) {
            throw new SolutionNotEmptyException("The solution " + solution.getName() + " still holds " + held
                    + " project(s). Delete them first.");
        }
        solutions.deleteById(id);
        audit.record(actor.entry(AuditOperation.SOLUTION_UPDATED, String.valueOf(id), "Solution deleted: " + solution.getName()));
    }

    // ------------------------------------------------------------------------------- projects

    public ProjectView createProject(long solutionId, String requestedName, String description, RequestActor actor) {
        SolutionEntity solution = requireSolution(solutionId);
        String name = BoundedText.required(requestedName, NAME_LENGTH, "A project name");
        refuseIfProjectNameTaken(solutionId, name, null);

        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutionId);
        project.setName(name);
        project.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        project.setCreatedAt(clock.instant());
        ProjectEntity saved = projects.save(project);

        audit.record(actor.entry(AuditOperation.PROJECT_UPDATED, String.valueOf(saved.getId()),
                "Project created: " + solution.getName() + " / " + name));
        return ProjectView.of(saved);
    }

    /** Either field may be null, which leaves it as it is; an empty description clears it. */
    public ProjectView updateProject(long id, String requestedName, String description, RequestActor actor) {
        ProjectEntity project = requireProject(id);
        String previous = project.getName();

        if (requestedName != null) {
            String name = BoundedText.required(requestedName, NAME_LENGTH, "A project name");
            refuseIfProjectNameTaken(project.getSolutionId(), name, id);
            project.setName(name);
        }
        if (description != null) {
            project.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        }
        ProjectEntity saved = projects.save(project);

        audit.record(actor.entry(AuditOperation.PROJECT_UPDATED, String.valueOf(id),
                "Project " + previous + " updated" + (previous.equals(saved.getName()) ? "" : " → " + saved.getName())));
        return ProjectView.of(saved);
    }

    /**
     * Deletes a project: its repositories return to "no project", its grants are revoked, and no
     * repository and no finding is deleted.
     *
     * <p><b>The grants go explicitly.</b> A grant names its target as {@code (kind, id)}, which no
     * foreign key can follow into three tables, so nothing would cascade: the row would stay on the
     * grant screens naming a deleted project, and should an engine ever hand the identifier out
     * again, it would grant a project nobody chose.
     *
     * <p><b>One transaction for the three writes</b>, opened here with a template because the
     * boundary starts inside this class; the audit entry is written after it commits, since it
     * opens its own and on SQLite would wait on this one's file lock.
     */
    public void deleteProject(long id, RequestActor actor) {
        ProjectEntity project = requireProject(id);
        record Removed(int detached, int grants) {}

        Removed removed = transactions.execute(status -> {
            int detached = repositories.detachProject(id);
            int grants = userTargets.deleteByTarget(TeamRules.KIND_PROJECT, id)
                    + teamTargets.deleteByTarget(TeamRules.KIND_PROJECT, id);
            projects.deleteById(id);
            return new Removed(detached, grants);
        });

        AuditLogService.Record deleted = actor.entry(AuditOperation.PROJECT_UPDATED, String.valueOf(id),
                "Project deleted: " + project.getName() + " (" + removed.detached()
                        + " repository(ies) returned to no project, " + removed.grants() + " grant(s) revoked)");
        audit.record(removed.grants() > 0 ? deleted.signalling(SecurityEventType.ACCESS_GRANT_CHANGED) : deleted);
    }

    // ------------------------------------------------------------------ filing a repository

    /**
     * Files a repository into a project, or moves it there from another.
     *
     * <p>Filing it where it already is changes nothing and records nothing: the route is a PUT, and
     * repeating it must not fill the log with moves that did not happen.
     *
     * @param allowed the caller's visibility. Only administrators reach this today, and they see
     *     everything; it is asked anyway, so that the day a narrower caller can file, a repository
     *     it cannot see answers the same 404 as one that does not exist
     */
    public void fileRepository(long projectId, long repositoryId, Visibility allowed, RequestActor actor) {
        ProjectEntity project = requireProject(projectId);
        RepositoryEntity repository = RowVisibility.requireVisible(repositories.findById(repositoryId).orElse(null), allowed);
        Long previousId = repository.getProjectId();
        if (Objects.equals(previousId, projectId)) {
            return;
        }

        repositories.assignProject(repositoryId, projectId);

        String name = TargetNaming.of(repository);
        String description = previousId == null
                ? "Repository " + name + " filed into project " + project.getName()
                        + ": holders of that project's grant now see it"
                : "Repository " + name + " moved from project " + projectName(previousId) + " to " + project.getName()
                        + ": visibility moves with it — holders of the first project's grant no longer see it through"
                        + " that grant, holders of the second now do";
        audit.record(actor.entry(AuditOperation.PROJECT_REPOSITORIES_CHANGED, String.valueOf(repositoryId), description));
    }

    /**
     * Takes a repository out of a project, back to "no project".
     *
     * <p>A repository that is not in this project is a 404 rather than a silent success: the
     * screen that sent it believes something the server does not, and should hear so.
     */
    public void removeRepository(long projectId, long repositoryId, Visibility allowed, RequestActor actor) {
        ProjectEntity project = requireProject(projectId);
        RepositoryEntity repository = RowVisibility.requireVisible(repositories.findById(repositoryId).orElse(null), allowed);
        if (!Objects.equals(repository.getProjectId(), projectId)) {
            throw new NoSuchElementException("This repository is not in that project.");
        }

        repositories.assignProject(repositoryId, null);

        audit.record(actor.entry(AuditOperation.PROJECT_REPOSITORIES_CHANGED, String.valueOf(repositoryId),
                "Repository " + TargetNaming.of(repository) + " removed from project " + project.getName()
                        + ": holders of that project's grant no longer see it through that grant"));
    }

    // -------------------------------------------------------------------------------- helpers

    private SolutionEntity requireSolution(long id) {
        return solutions.findById(id).orElseThrow(() -> new NoSuchElementException("Solution not found."));
    }

    private ProjectEntity requireProject(long id) {
        return projects.findById(id).orElseThrow(() -> new NoSuchElementException("Project not found."));
    }

    private String projectName(Long id) {
        return projects.findById(id).map(ProjectEntity::getName).orElse(TargetNaming.DELETED);
    }

    private void refuseIfSolutionNameTaken(String name, Long allowed) {
        Optional<SolutionEntity> existing = solutions.findByNameIgnoreCase(name);
        if (existing.isPresent() && !existing.get().getId().equals(allowed)) {
            // Here rather than left to the constraint, which answers a 500 carrying a driver's
            // message — and which folds case on MySQL and not on PostgreSQL.
            throw new IllegalArgumentException("A solution named \"" + name + "\" already exists.");
        }
    }

    private void refuseIfProjectNameTaken(long solutionId, String name, Long allowed) {
        Optional<ProjectEntity> existing = projects.findBySolutionIdAndNameIgnoreCase(solutionId, name);
        if (existing.isPresent() && !existing.get().getId().equals(allowed)) {
            throw new IllegalArgumentException("This solution already holds a project named \"" + name + "\".");
        }
    }
}
