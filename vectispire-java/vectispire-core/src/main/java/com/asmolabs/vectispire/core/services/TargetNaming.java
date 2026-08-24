package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.util.HashMap;
import java.util.Map;
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

    public TargetNaming(GitRepositories repositories, Containers containers) {
        this.repositories = repositories;
        this.containers = containers;
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
