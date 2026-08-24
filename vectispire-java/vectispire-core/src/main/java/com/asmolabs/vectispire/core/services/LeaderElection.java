package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.core.persistence.LeaderLeaseEntity;
import com.asmolabs.zanshin.core.repositories.LeaderLeases;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Taking, holding and losing the lease that makes a job single-owner.
 *
 * <p>Three operations, all built on one primitive: a conditional {@code UPDATE} whose affected
 * row count names the winner. That primitive is weaker than {@code SELECT … FOR UPDATE SKIP
 * LOCKED}, and it is enough here because what it protects is periodic and nearly idempotent:
 * two instances briefly believing themselves leader run a duplicate tick, not a corrupted row,
 * and the next tick settles it.
 *
 * <p><b>What "leader" covers, and what it deliberately does not.</b> The exclusive work is the
 * part of a tick that has an effect <em>per period</em> — dispatching due targets, the purge,
 * triage expiry, the outbox relay, reclaiming abandoned scans. Not the part that is per
 * instance by nature: every instance must go on claiming work for its own built-in worker, or
 * a fleet would sit idle behind whichever instance holds the lease.
 */
@Service
public class LeaderElection {

    private static final Logger log = LoggerFactory.getLogger(LeaderElection.class);

    /** The scheduler's lease. One row per exclusive job. */
    public static final String JOB_SCHEDULER = "scheduler";

    /**
     * This process, for the life of this process.
     *
     * <p><b>Not the host name</b>: two instances on one host is a deployment somebody will try,
     * and a host name could not tell them apart. Not persisted either — a restarted instance is
     * a new holder, which is exactly right, since it has forgotten what it was doing.
     */
    public static final String INSTANCE_ID = UUID.randomUUID().toString().replace("-", "");

    private final LeaderLeases leases;
    private final Duration leaseDuration;
    private final Clock clock;

    public LeaderElection(LeaderLeases leases, LeaderProperties properties, Clock clock) {
        this.leases = leases;
        this.leaseDuration = properties.lease();
        this.clock = clock;
    }

    /**
     * Takes or renews the lease. Says whether this process holds it.
     *
     * <p>Three cases in one method, because the caller does not care which: nobody has ever held
     * it, somebody holds it but let it expire, or we hold it already and are renewing.
     * <b>Renewal is what makes the leader stable</b> — a leader that had to win again every tick
     * would move the work around the fleet for no reason.
     *
     * @param at the instant the caller is also judging its work by. Passed in rather than read
     *     here: a lease taken at one instant while targets are judged at another is two clocks
     *     in one tick, one deciding who writes and the other deciding what
     */
    /*
     * Deliberately not one transaction. The read below is followed by a conditional update
     * whose `where` carries what was read, so the arbitration is in the statement rather than
     * in an isolation level — and a losing insert must not poison a transaction that then
     * refuses to commit the "we did not get it" answer.
     */
    public boolean acquire(String name, String holder, Instant at) {
        Instant expiresAt = at.plus(leaseDuration);
        Optional<LeaderLeaseEntity> existing = leases.findById(name);

        if (existing.isEmpty()) {
            return create(name, holder, at, expiresAt);
        }

        LeaderLeaseEntity lease = existing.get();
        boolean mine = holder.equals(lease.getHolder());
        boolean expired = lease.getExpiresAt() == null || !lease.getExpiresAt().isAfter(at);
        if (!mine && !expired) {
            return false;
        }

        // Conditioned on the holder **and** on the expiry we have just read: if another instance
        // took the lease between the read and this update, its row count is zero and we lose —
        // rather than stealing a lease somebody legitimately holds.
        int updated = mine ? leases.renew(name, holder, expiresAt, at) : takeOver(lease, name, holder, expiresAt, at);

        if (updated > 0 && !mine) {
            log.info("Instance {} took the \"{}\" lease.", holder, name);
        }
        return updated > 0;
    }

    public boolean acquire() {
        return acquire(JOB_SCHEDULER, INSTANCE_ID, clock.instant());
    }

    /**
     * Releases the lease, so a successor takes it at once instead of waiting for expiry.
     *
     * <p>Called at shutdown. Best-effort by nature — a killed process releases nothing, which is
     * exactly why expiry exists and why nothing depends on this path.
     */
    @Transactional
    public boolean release(String name, String holder) {
        return leases.release(name, holder, clock.instant()) > 0;
    }

    public boolean release() {
        return release(JOB_SCHEDULER, INSTANCE_ID);
    }

    /**
     * Who holds the lease at this instant, or empty when it is free or stale.
     *
     * <p>For display and diagnosis: "why is nothing happening" is a question this answers.
     */
    @Transactional(readOnly = true)
    public Optional<String> currentHolder(String name, Instant at) {
        return leases.findById(name)
                .filter(lease -> lease.getHolder() != null)
                .filter(lease -> lease.getExpiresAt() != null && lease.getExpiresAt().isAfter(at))
                .map(LeaderLeaseEntity::getHolder);
    }

    /** Does this process hold the lease, without taking it? */
    @Transactional(readOnly = true)
    public boolean isLeader(String name, String holder, Instant at) {
        return currentHolder(name, at).filter(holder::equals).isPresent();
    }

    /**
     * A released lease and an expired one are taken over by different statements.
     *
     * <p>Not a style choice: comparing a bare parameter to {@code null} in JPQL leaves
     * PostgreSQL unable to infer its type, and the single-statement version failed there while
     * passing on the other three. See {@code LeaderLeases.takeOverFrom}.
     */
    private int takeOver(LeaderLeaseEntity lease, String name, String holder, Instant expiresAt, Instant at) {
        if (lease.getHolder() == null || lease.getExpiresAt() == null) {
            return leases.takeOverReleased(name, holder, expiresAt, at);
        }
        return leases.takeOverFrom(name, holder, expiresAt, at, lease.getHolder(), lease.getExpiresAt());
    }

    /**
     * First acquisition.
     *
     * <p>Two instances started together both try this, and <b>the primary key arbitrates</b>: the
     * loser catches the constraint violation and will try again on the next tick.
     */
    private boolean create(String name, String holder, Instant at, Instant expiresAt) {
        try {
            leases.insertNew(name, holder, at, expiresAt, at);
            log.info("Instance {} took the \"{}\" lease.", holder, name);
            return true;
        } catch (DataAccessException lostTheRace) {
            return false;
        }
    }
}
