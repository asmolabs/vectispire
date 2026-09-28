package com.asmolabs.vectispire.core.maintenance;

import com.asmolabs.vectispire.core.maintenance.persistence.OneShotJobRepository;
import java.time.Clock;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The jobs that run once per database, whatever the number of instances starting.
 *
 * <p><b>A read of "has it run?" cannot decide this.</b> The repair of withheld claims read its own
 * audit entry: two instances starting together both found none, both ran, and both wrote one. The
 * decision is the primary key's: {@link #claim} inserts the job's name, and of two instances only one
 * insert succeeds — the other waits for the first transaction to end and then fails, or, on SQLite,
 * waits for the file's write lock and fails the same way.
 */
@Service
public class OneShotJobs {

    private final OneShotJobRepository jobs;
    private final Clock clock;

    public OneShotJobs(OneShotJobRepository jobs, Clock clock) {
        this.jobs = jobs;
        this.clock = clock;
    }

    /**
     * Takes the job for this caller, and says whether it did.
     *
     * <p><b>First, in the transaction that does the job's work</b> ({@code MANDATORY}): the row and
     * the work commit together, so a job that fails half-way is not recorded as run, and an instance
     * that crashes before its commit leaves the job to the next start. {@code false} means another
     * transaction holds or has committed the row — or the insert failed for another reason, which the
     * next start retries since nothing was recorded. <b>On {@code false} the caller rolls its
     * transaction back</b> and does nothing: a failed statement has already marked it rollback-only,
     * and on PostgreSQL it accepts no further statement.
     *
     * @param name at most 64 characters, the column's width
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public boolean claim(String name) {
        try {
            return jobs.claim(name, clock.instant()) == 1;
        } catch (DataAccessException takenOrFailed) {
            return false;
        }
    }
}
