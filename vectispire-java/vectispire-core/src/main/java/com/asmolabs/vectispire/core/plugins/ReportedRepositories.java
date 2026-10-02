package com.asmolabs.vectispire.core.plugins;

import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Tells the module above that a report was accepted for a repository ({@link RepositoryReported}), once
 * for the three kinds of import, <b>inside the import's transaction</b> (decision 0033).
 *
 * <p>It was called after the commit and the audit entry, and whatever the reaction threw was logged and
 * dropped: a process stopping in between answered nothing for that report. The reaction now only queues
 * what it will do, in the import's transaction, so it commits with the import or not at all, and does
 * its work later, from the outbox, where a failure is retried instead of logged and lost. Nothing is
 * caught here any more: a failure to queue is a failure of the write it belongs to.
 */
@Component
class ReportedRepositories {

    private final Optional<RepositoryReported> reported;

    ReportedRepositories(Optional<RepositoryReported> reported) {
        this.reported = reported;
    }

    /** Called inside the import's transaction, after its rows are saved. */
    void announce(long repositoryId) {
        reported.ifPresent(listener -> listener.reported(repositoryId));
    }
}
