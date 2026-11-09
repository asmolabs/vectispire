package com.asmolabs.vectispire.core.maintenance;

import com.asmolabs.vectispire.core.maintenance.persistence.OneShotJobRepository;
import java.time.Clock;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The jobs that run once per database, whatever the number of instances starting.
 *
 * <p><b>A read of "has it run?" cannot decide this.</b> The repair of withheld claims read its own
 * audit entry: two instances starting together both found none, both ran, and both wrote one. The
 * decision is the primary key's: {@link #claim} inserts the job's name, and of two instances only one
 * insert succeeds — the other waits for the first transaction to end and then fails.
 *
 * <p><b>And a failed insert does not say why it failed.</b> The loser's refusal arrives as a
 * {@code DataIntegrityViolationException} on PostgreSQL and MySQL — and arrived as a bare {@code
 * JpaSystemException} on the SQLite fixture of the time; a lock that timed out or a connection that
 * dropped fails the same statement. The first version read every
 * failure as "taken elsewhere" — a claim that failed for any reason would have been reported as
 * somebody else's while nobody ran the job. So the failure is thrown, and only the row answers:
 * {@link #hasRun}, read after the rollback, is what tells a lost claim from a failed one.
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
     * Takes the job for this caller, or throws.
     *
     * <p><b>First, in the transaction that does the job's work</b> ({@code MANDATORY}): the row and
     * the work commit together, so a job that fails half-way is not recorded as run, and an instance
     * that crashes before its commit leaves the job to the next start. A throw leaves the caller's
     * transaction unusable — on PostgreSQL it accepts no further statement — so the caller lets it
     * roll back and then asks {@link #hasRun}: yes means another instance holds it, no means the
     * claim failed and the next start retries.
     *
     * @param name at most 64 characters, the column's width
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void claim(String name) {
        jobs.claim(name, clock.instant());
    }

    /**
     * Whether a committed row holds the job. After the rollback of a claim that threw, and never
     * inside that transaction: in it PostgreSQL would refuse the read, and the other engines would
     * answer for a snapshot that may predate the winner's commit.
     */
    @Transactional(readOnly = true, propagation = Propagation.REQUIRES_NEW)
    public boolean hasRun(String name) {
        return jobs.existsById(name);
    }
}
