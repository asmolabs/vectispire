package com.asmolabs.vectispire.core.services.shared;

import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Projects;
import com.asmolabs.vectispire.core.repositories.Solutions;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * What a target is called on a screen, in an alert and in a ticket.
 *
 * <p>One place, because a name computed three ways is three names for one thing, and the
 * mismatch surfaces where it costs most: an alert naming a repository one way and the ticket
 * opened from it naming the same repository another.
 */
@Service
public class TargetNaming {

    /** Said explicitly rather than shown as a blank: a scan's history stays useful after its target is gone. */
    public static final String DELETED = "deleted target";

    private final GitRepositories repositories;
    private final Containers containers;
    private final Projects projects;
    private final Solutions solutions;

    public TargetNaming(GitRepositories repositories, Containers containers, Projects projects, Solutions solutions) {
        this.repositories = repositories;
        this.containers = containers;
        this.projects = projects;
        this.solutions = solutions;
    }

    /** A grant as the account and team administration hold one: a kind and an identifier. */
    public interface Grant {
        String kind();

        Long id();
    }

    /**
     * A grant as a screen lists it.
     *
     * <p>Named here rather than left to the client to look up. The client used to label a grant
     * from the list of repositories and images it fetched for the selector; a project is in
     * neither, so a project grant would have been listed as a bare number — or, worse, not at all,
     * on the screen whose job is to say what somebody can read.
     *
     * @param name what the target is called now, {@link TargetNaming#DELETED} when it no longer exists — a
     *     grant row outliving its target is worth seeing rather than hiding
     */
    public record TargetGrant(String kind, Long id, String name) {}

    /** The grants, in the order given, each with its target's name — three queries at most. */
    @Transactional(readOnly = true)
    public List<TargetGrant> named(List<? extends Grant> grants) {
        Names names = forIds(idsOf(grants, TeamRules.KIND_REPOSITORY), idsOf(grants, TeamRules.KIND_CONTAINER));
        Map<Long, String> projectNames = projectNames(idsOf(grants, TeamRules.KIND_PROJECT));
        return grants.stream()
                .map(grant -> new TargetGrant(grant.kind(), grant.id(), switch (grant.kind()) {
                    case TeamRules.KIND_REPOSITORY -> names.of(grant.id(), null);
                    case TeamRules.KIND_CONTAINER -> names.of(null, grant.id());
                    case TeamRules.KIND_PROJECT -> projectNames.getOrDefault(grant.id(), DELETED);
                    default -> DELETED;
                }))
                .toList();
    }

    /**
     * Projects' names, each qualified by its solution.
     *
     * <p>Qualified because a project's name is unique only within its solution: two solutions may
     * each hold an "API", and a grant list reading "API" twice cannot say which is which.
     */
    @Transactional(readOnly = true)
    public Map<Long, String> projectNames(Collection<Long> projectIds) {
        if (projectIds.isEmpty()) {
            return Map.of();
        }
        List<ProjectEntity> found = projects.findAllById(projectIds);
        Map<Long, SolutionEntity> bySolution = solutions
                .findAllById(found.stream().map(ProjectEntity::getSolutionId).collect(Collectors.toSet()))
                .stream()
                .collect(Collectors.toMap(SolutionEntity::getId, Function.identity()));
        Map<Long, String> named = new HashMap<>();
        found.forEach(project -> named.put(project.getId(), of(project, bySolution.get(project.getSolutionId()))));
        return named;
    }

    /** {@code Solution / Project}, or the project's name alone should its solution be unreadable. */
    public static String of(ProjectEntity project, SolutionEntity solution) {
        return solution == null ? project.getName() : solution.getName() + " / " + project.getName();
    }

    private static Set<Long> idsOf(List<? extends Grant> grants, String kind) {
        return grants.stream()
                .filter(grant -> kind.equals(grant.kind()))
                .map(Grant::id)
                .collect(Collectors.toSet());
    }

    /** @param repositories and {@code containers} keyed by identifier, both resolved in one pass */
    public record Names(Map<Long, String> repositories, Map<Long, String> containers) {

        /** {@code container} whenever a container id is set: only one of the two ever is. */
        public String kindOf(Long containerId) {
            return containerId != null ? "container" : "repository";
        }

        public String of(Long repoId, Long containerId) {
            if (repoId != null) {
                return repositories.getOrDefault(repoId, DELETED);
            }
            if (containerId != null) {
                return containers.getOrDefault(containerId, DELETED);
            }
            return DELETED;
        }
    }

    /**
     * The names for a known set of identifiers.
     *
     * <p>{@link #all()} suits a screen that shows every target anyway; this one suits a page of
     * fifty backlog rows on an estate of two thousand repositories, where loading them all to
     * name four is the wrong shape of query.
     */
    @Transactional(readOnly = true)
    public Names forIds(java.util.Collection<Long> repositoryIds, java.util.Collection<Long> containerIds) {
        Map<Long, String> byRepository = new HashMap<>();
        repositories.findAllById(repositoryIds).forEach(row -> byRepository.put(row.getId(), of(row)));

        Map<Long, String> byContainer = new HashMap<>();
        containers.findAllById(containerIds).forEach(row -> byContainer.put(row.getId(), of(row)));

        return new Names(byRepository, byContainer);
    }

    /**
     * Every target's name, in two queries.
     *
     * <p>Loaded whole rather than one lookup per row: a list of two hundred scans would
     * otherwise issue two hundred queries for a table that holds a handful of rows.
     */
    @Transactional(readOnly = true)
    public Names all() {
        Map<Long, String> byRepository = new HashMap<>();
        repositories.findAll().forEach(repository -> byRepository.put(repository.getId(), of(repository)));

        Map<Long, String> byContainer = new HashMap<>();
        containers.findAll().forEach(container -> byContainer.put(container.getId(), of(container)));

        return new Names(byRepository, byContainer);
    }

    /**
     * The operator's name for it, or the short form of the URL when they gave none.
     *
     * <p><b>Through the domain's rule rather than a copy of it.</b> This method was that copy,
     * and returned the whole clone URL where {@link RepositoryUrl#displayName} returns
     * {@code org/project} — so the same repository was called two things depending on which
     * screen asked. The short form is also the only one that fits in a table column.
     */
    public static String of(RepositoryEntity repository) {
        return RepositoryUrl.displayName(repository.getName(), repository.getUrl());
    }

    public static String of(ContainerEntity container) {
        return new ImageReference(container.getRegistry(), container.getImageName(), container.getTag())
                .displayName();
    }
}
