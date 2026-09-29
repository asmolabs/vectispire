package com.asmolabs.vectispire.core.plugins;

import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Tells the module above that a report was accepted for a repository ({@link RepositoryReported}), once
 * for the three kinds of import, and never at the import's expense: the pipeline that sent the report is
 * answered for what was recorded, and whatever the reaction throws is logged and dropped here.
 */
@Component
class ReportedRepositories {

    private static final Logger log = LoggerFactory.getLogger(ReportedRepositories.class);

    private final Optional<RepositoryReported> reported;

    ReportedRepositories(Optional<RepositoryReported> reported) {
        this.reported = reported;
    }

    /** Called after the import's commit and its audit entry. */
    void announce(long repositoryId) {
        reported.ifPresent(listener -> {
            try {
                listener.reported(repositoryId);
            } catch (RuntimeException failed) {
                log.warn("A report for repository {} was recorded, and what reacts to it failed — the import stands: {}",
                        repositoryId, failed.toString());
            }
        });
    }
}
