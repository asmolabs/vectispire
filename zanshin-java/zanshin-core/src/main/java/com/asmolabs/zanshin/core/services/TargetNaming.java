package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.targets.ImageReference;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
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

    /** The operator's name for it, or the URL when they gave none. */
    public static String of(RepositoryEntity repository) {
        String name = repository.getName() == null ? "" : repository.getName().trim();
        return name.isEmpty() ? repository.getUrl() : name;
    }

    public static String of(ContainerEntity container) {
        return new ImageReference(container.getRegistry(), container.getImageName(), container.getTag())
                .displayName();
    }
}
