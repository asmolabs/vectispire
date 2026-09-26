package com.asmolabs.vectispire.core.services.targets;

import com.asmolabs.vectispire.common.domain.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.targets.TargetDeleted;
import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Deleting a target, atomically with every row that names it, on both deployable engines and on the
 * SQLite fixture.
 *
 * <p><b>This class deletes the target and announces it; each domain purges its own rows.</b> It used
 * to issue every delete itself — grants, gate policies, issues, triage events, ticket links,
 * findings, components, AI reviews, scans — which made the owner of repositories the one class that
 * knew seven other domains' tables. The order those purges run in, children before parents, is
 * {@link TargetPurge.Phase}'s.
 *
 * <p><b>Published inside the transaction, heard inside it.</b> The listeners are synchronous and
 * declare {@code MANDATORY}: the purge and the deletion commit together or not at all. An
 * after-commit listener would leave a window — and, on any failure, a permanent state — in which the
 * target is gone and its issues, grants and scans remain.
 */
@Service
public class TargetDeletionService {

    private static final Logger log = LoggerFactory.getLogger(TargetDeletionService.class);

    private final GitRepositories repositories;
    private final Containers containers;
    private final ApplicationEventPublisher events;

    public TargetDeletionService(GitRepositories repositories, Containers containers, ApplicationEventPublisher events) {
        this.repositories = repositories;
        this.containers = containers;
        this.events = events;
    }

    @Transactional
    public void deleteContainer(long containerId) {
        events.publishEvent(new TargetDeleted(new ScanTarget.Container(containerId)));
        containers.deleteById(containerId);
        log.info("Container {} deleted.", containerId);
    }

    @Transactional
    public void deleteRepository(long repoId) {
        events.publishEvent(new TargetDeleted(new ScanTarget.Repository(repoId)));
        repositories.deleteById(repoId);
        log.info("Repository {} deleted.", repoId);
    }

    /**
     * Purges any orphaned issues or scans whose parent repository/container no longer exists.
     * Triggered automatically on startup and available for periodic maintenance.
     */
    @Transactional
    @EventListener(ApplicationReadyEvent.class)
    public void purgeOrphanedTargetData() {
        events.publishEvent(new OrphanedTargetRows());
    }
}
