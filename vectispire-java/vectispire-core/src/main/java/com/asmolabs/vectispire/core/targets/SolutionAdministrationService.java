package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.TargetGrants;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Solutions, their projects, and which project a repository or an image is filed in (decision 0023,
 * and its amendment of 2026-09-30 for images).
 *
 * <p><b>One service for both levels, and the read elsewhere.</b> The writes share their invariants
 * — a solution is deleted only when it holds no project, a project's name is unique within its
 * solution, a repository or an image is in at most one project — and splitting solutions from projects would
 * put each half of those rules in a different class. The tree is {@link SolutionQueryService}'s,
 * because it is decided by the reader's visibility and computes figures, which no write here does.
 *
 * <p><b>Filing a repository or an image is an access change.</b> A project grant resolves at each
 * request into the project's repositories and images, so a move changes what the project's grantees see at once, in
 * both directions, with no grant row touched. That is the whole point of the decision and also its
 * sharpest edge, so every move is audited in words that say it.
 *
 * <p>Refusals follow the house convention: {@link InvalidInputException} for what the
 * administrator can correct (400), {@link NotFoundException} for what is not there or not
 * visible (404, in one sentence for both), {@link SolutionNotEmptyException} for a deletion the
 * current state forbids, and {@link SolutionNameTakenException} and {@link ProjectNameTakenException}
 * for a name already held (409, each with its type).
 */
@Service
public class SolutionAdministrationService {

    /** The width of {@code t_solution.name} and {@code t_project.name}. */
    static final int NAME_LENGTH = 100;

    /** The width of both {@code description} columns. */
    static final int DESCRIPTION_LENGTH = 255;

    private final SolutionRepository solutions;
    private final ProjectRepository projects;
    private final GitRepositoryRepository repositories;
    private final ContainerRepository containers;
    private final TargetGrants grants;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    public SolutionAdministrationService(
            SolutionRepository solutions,
            ProjectRepository projects,
            GitRepositoryRepository repositories,
            ContainerRepository containers,
            TargetGrants grants,
            AuditLogService audit,
            TransactionTemplate transactions,
            ApplicationEventPublisher events,
            Clock clock) {
        this.solutions = solutions;
        this.projects = projects;
        this.repositories = repositories;
        this.containers = containers;
        this.grants = grants;
        this.audit = audit;
        this.transactions = transactions;
        this.events = events;
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
        List<AuditLogService.Record> entries = new ArrayList<>();
        SolutionView created = createSolution(requestedName, description, actor, entries);
        entries.forEach(audit::record);
        return created;
    }

    /**
     * {@link #createSolution(String, String, RequestActor)} inside a transaction somebody else holds — decision
     * 0037's import, through {@code TargetImports}: the same refusals and the same entry, handed to {@code entries}
     * for the holder to record once it has committed.
     */
    SolutionView createSolution(
            String requestedName, String description, RequestActor actor, List<AuditLogService.Record> entries) {
        String name = BoundedText.required(requestedName, NAME_LENGTH, "A solution name");
        refuseIfSolutionNameTaken(name, null);

        SolutionEntity solution = new SolutionEntity();
        solution.setName(name);
        solution.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        solution.setCreatedAt(clock.instant());
        SolutionEntity saved = solutions.save(solution);

        entries.add(actor.entry(AuditOperation.SOLUTION_UPDATED, String.valueOf(saved.getId()), "Solution created: " + name));
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
                    + " project(s). Move them to another solution or delete them first.");
        }
        solutions.deleteById(id);
        audit.record(actor.entry(AuditOperation.SOLUTION_UPDATED, String.valueOf(id), "Solution deleted: " + solution.getName()));
    }

    /**
     * A solution name another solution holds, case aside: 409, with the type {@code
     * urn:vectispire:problem:solution-name-taken} — the rule {@link ProjectNameTakenException} follows,
     * one level up, so the two names of the tree are refused alike.
     */
    public static final class SolutionNameTakenException extends ConflictException {

        /** The token the problem's {@code type} ends with, published in the routes' descriptions. */
        public static final String CAUSE = "solution-name-taken";

        SolutionNameTakenException(String message) {
            super(message, CAUSE);
        }
    }

    // ------------------------------------------------------------------------------- projects

    public ProjectView createProject(long solutionId, String requestedName, String description, RequestActor actor) {
        List<AuditLogService.Record> entries = new ArrayList<>();
        ProjectView created = createProject(solutionId, requestedName, description, actor, entries);
        entries.forEach(audit::record);
        return created;
    }

    /** {@link #createProject(long, String, String, RequestActor)} inside a transaction somebody else holds, as above. */
    ProjectView createProject(long solutionId, String requestedName, String description, RequestActor actor,
            List<AuditLogService.Record> entries) {
        SolutionEntity solution = requireSolution(solutionId);
        String name = BoundedText.required(requestedName, NAME_LENGTH, "A project name");
        refuseIfProjectNameTaken(solutionId, name, null);

        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutionId);
        project.setName(name);
        project.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        project.setCreatedAt(clock.instant());
        ProjectEntity saved = projects.save(project);

        entries.add(actor.entry(AuditOperation.PROJECT_UPDATED, String.valueOf(saved.getId()),
                "Project created: " + solution.getName() + " / " + name));
        return ProjectView.of(saved);
    }

    /** The solution of that name, case aside — the rule a creation refuses a second one by. */
    Optional<SolutionView> solutionNamed(String name) {
        return solutions.findByNameIgnoreCase(name).map(SolutionView::of);
    }

    /** The project of that name in the solution, case aside — the rule a creation refuses a second one by. */
    Optional<ProjectView> projectNamed(long solutionId, String name) {
        return projects.findBySolutionIdAndNameIgnoreCase(solutionId, name).map(ProjectView::of);
    }

    /**
     * Renames, describes or moves a project to another solution; any of the three may be null, which
     * leaves it as it is, and an empty description clears it.
     *
     * <p><b>A move takes everything with it and changes nobody's access.</b> Every row naming a
     * project names it by its identifier — its repositories ({@code t_repository.project_id}), its
     * images ({@code t_container.project_id}), its grants, its checklists, its plugin activations, its SARIF sources — and nothing names a
     * solution but {@code t_project.solution_id}: no grant is written for a solution (decision 0023),
     * and the backlog's {@code solution_id} filter resolves the solution's repositories at each
     * request, and its images with them. So the one column moves, and there is nothing to carry and nothing left behind.
     *
     * <p><b>The same solution is no move</b>, not a refusal: a PATCH that sends the value the project
     * already holds asks for the state it is in, and a screen that sends the whole form back must not
     * be told it erred.
     *
     * <p><b>A name taken in the solution the project ends up in is a 409</b> ({@link
     * ProjectNameTakenException}), whether the request renames it, moves it or both: the request is well
     * formed and the solution's state forbids it, and a client that renames the other project first — a
     * gesture the request does not contain — succeeds with the same request.
     *
     * @param solutionId the solution to move the project to, or null to leave it where it is
     * @param allowed the caller's visibility. A move rearranges the tree every reader is shown and is
     *     only asked of one who sees the whole estate — the target solution empty or not, the project
     *     whole or not. Only administrators reach this today, and they see everything; anyone narrower
     *     is answered the 404 an absent solution gets, so that the refusal confirms nothing
     */
    public ProjectView updateProject(
            long id, String requestedName, String description, Long solutionId, Visibility allowed, RequestActor actor) {
        ProjectEntity project = requireProject(id);
        String previous = project.getName();
        Long previousSolutionId = project.getSolutionId();

        SolutionEntity target = null;
        if (solutionId != null && !solutionId.equals(previousSolutionId)) {
            if (!(allowed instanceof Visibility.Everything)) {
                throw new NotFoundException(SOLUTION_NOT_FOUND);
            }
            target = requireSolution(solutionId);
        }

        String name = requestedName == null ? previous : BoundedText.required(requestedName, NAME_LENGTH, "A project name");
        if (target != null) {
            refuseIfNameTakenInTarget(target, name);
            project.setSolutionId(target.getId());
        } else if (requestedName != null) {
            refuseIfProjectNameTaken(previousSolutionId, name, id);
        }
        project.setName(name);
        if (description != null) {
            project.setDescription(BoundedText.optional(description, DESCRIPTION_LENGTH, "The description"));
        }
        ProjectEntity saved = projects.save(project);

        String change = "Project " + previous + " updated" + (previous.equals(saved.getName()) ? "" : " → " + saved.getName());
        if (target != null) {
            change += "; moved from solution " + solutionName(previousSolutionId) + " to " + target.getName()
                    + " (its repositories, images, grants and checklists follow it)";
        }
        audit.record(actor.entry(AuditOperation.PROJECT_UPDATED, String.valueOf(id), change));
        return ProjectView.of(saved);
    }

    /**
     * A project name already held in the solution — on creation, on a rename, on a move: 409, with the
     * type {@code urn:vectispire:problem:project-name-taken}, so that a screen offers to rename rather
     * than parse the sentence.
     *
     * <p><b>One code for the three gestures.</b> A rename answered 400 while a move answered 409 for the
     * same fact — the name is held — and a client had to know which gesture it had made to read the
     * refusal. The name is not malformed (that is the 400: empty, too long); the solution's state
     * forbids it, and the same request succeeds once the other project is renamed.
     */
    public static final class ProjectNameTakenException extends ConflictException {

        /** The token the problem's {@code type} ends with, published in the route's description. */
        public static final String CAUSE = "project-name-taken";

        ProjectNameTakenException(String message) {
            super(message, CAUSE);
        }
    }

    /**
     * Deletes a project: its repositories and its images return to "no project", its grants are
     * revoked, and no repository, no image and no finding is deleted.
     *
     * <p><b>The grants go explicitly.</b> A grant names its target as {@code (kind, id)}, which no
     * foreign key can follow into three tables, so nothing would cascade: the row would stay on the
     * grant screens naming a deleted project, and should an engine ever hand the identifier out
     * again, it would grant a project nobody chose.
     *
     * <p><b>One transaction for the writes</b>, opened here with a template because the
     * boundary starts inside this class; the audit entry is written after it commits, since it
     * opens its own and inside this one would describe a deletion that may still roll back.
     */
    public void deleteProject(long id, RequestActor actor) {
        ProjectEntity project = requireProject(id);
        record Removed(int detached, int detachedImages, int grants) {}

        Removed removed = transactions.execute(status -> {
            int detached = repositories.detachProject(id);
            int detachedImages = containers.detachProject(id);
            int revoked = grants.revokeAll(TeamRules.KIND_PROJECT, id).grants();
            // Modules above that keep rows naming the project drop theirs here, in this transaction
            // (ProjectDeleted): the plugins activated for it, the SARIF sources scoped to it.
            events.publishEvent(new ProjectDeleted(id));
            projects.deleteById(id);
            return new Removed(detached, detachedImages, revoked);
        });

        AuditLogService.Record deleted = actor.entry(AuditOperation.PROJECT_UPDATED, String.valueOf(id),
                "Project deleted: " + project.getName() + " (" + removed.detached()
                        + " repository(ies) and " + removed.detachedImages() + " image(s) returned to no project, "
                        + removed.grants() + " grant(s) revoked)");
        audit.record(removed.grants() > 0 ? deleted.signalling(SecurityEventType.ACCESS_GRANT_CHANGED) : deleted);
    }

    /**
     * A project as the routes answer it, or empty when there is none — for a module above that names
     * a project in its own rows (plugin activations, SARIF sources) and must refuse one that does not
     * exist before writing it.
     */
    public Optional<ProjectView> project(long id) {
        return projects.findById(id).map(ProjectView::of);
    }

    /**
     * How a row naming a project shows it: the project's name and its solution's.
     *
     * @param solutionName null only when the solution row could not be read, which the schema's key
     *     does not allow — never an invented name
     */
    public record ProjectLabel(long id, String name, Long solutionId, String solutionName) {}

    /**
     * The labels of these projects, for a module above that lists rows naming a project (plugin
     * activations) and would otherwise leave the screen to load the whole tree for the names. A
     * project that does not exist is missing from the map.
     *
     * <p>No visibility here: the caller decides who reads the rows, and a project's name is shown to
     * exactly those who may read them. <b>One lookup per {@link #LOOKUP_BATCH} ids</b> — the list is
     * sized by the data, and one bind parameter per element fails past the PostgreSQL driver's 65,535.
     */
    public Map<Long, ProjectLabel> projectLabels(Collection<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return Map.of();
        }
        List<ProjectEntity> found = new ArrayList<>();
        List<Long> distinct = ids.stream().filter(Objects::nonNull).distinct().toList();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            found.addAll(projects.findAllById(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size()))));
        }
        List<Long> solutionIds = found.stream().map(ProjectEntity::getSolutionId).filter(Objects::nonNull).distinct().toList();
        Map<Long, String> solutionNames = new HashMap<>();
        for (int from = 0; from < solutionIds.size(); from += LOOKUP_BATCH) {
            solutions.findAllById(solutionIds.subList(from, Math.min(from + LOOKUP_BATCH, solutionIds.size())))
                    .forEach(solution -> solutionNames.put(solution.getId(), solution.getName()));
        }
        Map<Long, ProjectLabel> labels = new HashMap<>();
        for (ProjectEntity project : found) {
            labels.put(project.getId(), new ProjectLabel(project.getId(), project.getName(), project.getSolutionId(),
                    project.getSolutionId() == null ? null : solutionNames.get(project.getSolutionId())));
        }
        return Map.copyOf(labels);
    }

    /** How many identifiers one lookup binds: far under every engine's limit. */
    static final int LOOKUP_BATCH = 1_000;

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
        RepositoryEntity repository = RowVisibility.requireVisibleRepository(repositories.findById(repositoryId).orElse(null), repositoryId, allowed);
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
        RepositoryEntity repository = RowVisibility.requireVisibleRepository(repositories.findById(repositoryId).orElse(null), repositoryId, allowed);
        if (!Objects.equals(repository.getProjectId(), projectId)) {
            throw new NotFoundException("This repository is not in that project.");
        }

        repositories.assignProject(repositoryId, null);

        audit.record(actor.entry(AuditOperation.PROJECT_REPOSITORIES_CHANGED, String.valueOf(repositoryId),
                "Repository " + TargetNaming.of(repository) + " removed from project " + project.getName()
                        + ": holders of that project's grant no longer see it through that grant"));
    }

    // ----------------------------------------------------------------------- filing an image

    /**
     * Files a container image into a project, or moves it there from another — the repository's rule
     * (amendment of 2026-09-30): at most one project, a move moves its visibility for both projects'
     * grantees, and filing it where it already is changes and records nothing.
     *
     * @param allowed the caller's visibility; an image it cannot see answers the 404 an absent one gets
     */
    public void fileContainer(long projectId, long containerId, Visibility allowed, RequestActor actor) {
        ProjectEntity project = requireProject(projectId);
        ContainerEntity container = RowVisibility.requireVisible(
                containers.findById(containerId), new ScanTarget.Container(containerId), allowed);
        Long previousId = container.getProjectId();
        if (Objects.equals(previousId, projectId)) {
            return;
        }

        containers.assignProject(containerId, projectId);

        String name = TargetNaming.of(container);
        String description = previousId == null
                ? "Image " + name + " filed into project " + project.getName()
                        + ": holders of that project's grant now see it"
                : "Image " + name + " moved from project " + projectName(previousId) + " to " + project.getName()
                        + ": visibility moves with it — holders of the first project's grant no longer see it through"
                        + " that grant, holders of the second now do";
        audit.record(actor.entry(AuditOperation.PROJECT_CONTAINERS_CHANGED, String.valueOf(containerId), description));
    }

    /**
     * Takes an image out of a project, back to "no project"; one that is not in this project is a 404,
     * as for a repository.
     */
    public void removeContainer(long projectId, long containerId, Visibility allowed, RequestActor actor) {
        ProjectEntity project = requireProject(projectId);
        ContainerEntity container = RowVisibility.requireVisible(
                containers.findById(containerId), new ScanTarget.Container(containerId), allowed);
        if (!Objects.equals(container.getProjectId(), projectId)) {
            throw new NotFoundException("This image is not in that project.");
        }

        containers.assignProject(containerId, null);

        audit.record(actor.entry(AuditOperation.PROJECT_CONTAINERS_CHANGED, String.valueOf(containerId),
                "Image " + TargetNaming.of(container) + " removed from project " + project.getName()
                        + ": holders of that project's grant no longer see it through that grant"));
    }

    // -------------------------------------------------------------------------------- helpers

    /** Absent and hidden in the same words. */
    private static final String SOLUTION_NOT_FOUND = "Solution not found.";

    private SolutionEntity requireSolution(long id) {
        return solutions.findById(id).orElseThrow(() -> new NotFoundException(SOLUTION_NOT_FOUND));
    }

    private String solutionName(Long id) {
        return id == null ? TargetNaming.DELETED : solutions.findById(id).map(SolutionEntity::getName).orElse(TargetNaming.DELETED);
    }

    private void refuseIfNameTakenInTarget(SolutionEntity target, String name) {
        if (projects.findBySolutionIdAndNameIgnoreCase(target.getId(), name).isPresent()) {
            throw new ProjectNameTakenException("The solution " + target.getName() + " already holds a project named \""
                    + name + "\". Rename one of the two before moving.");
        }
    }

    private ProjectEntity requireProject(long id) {
        return projects.findById(id).orElseThrow(() -> new NotFoundException("Project not found."));
    }

    private String projectName(Long id) {
        return projects.findById(id).map(ProjectEntity::getName).orElse(TargetNaming.DELETED);
    }

    private void refuseIfSolutionNameTaken(String name, Long allowed) {
        Optional<SolutionEntity> existing = solutions.findByNameIgnoreCase(name);
        if (existing.isPresent() && !existing.get().getId().equals(allowed)) {
            // Here rather than left to the constraint, which answers a 500 carrying a driver's
            // message — and which folds case on MySQL and not on PostgreSQL.
            throw new SolutionNameTakenException("A solution named \"" + name + "\" already exists.");
        }
    }

    private void refuseIfProjectNameTaken(long solutionId, String name, Long allowed) {
        Optional<ProjectEntity> existing = projects.findBySolutionIdAndNameIgnoreCase(solutionId, name);
        if (existing.isPresent() && !existing.get().getId().equals(allowed)) {
            throw new ProjectNameTakenException("This solution already holds a project named \"" + name + "\".");
        }
    }
}
