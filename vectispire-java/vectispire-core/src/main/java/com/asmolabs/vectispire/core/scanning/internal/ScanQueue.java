package com.asmolabs.vectispire.core.scanning.internal;

import static com.asmolabs.vectispire.common.domain.scans.ScanQueue.LEASE_EXHAUSTED_MESSAGE;
import static com.asmolabs.vectispire.common.domain.scans.ScanQueue.afterLapse;
import static com.asmolabs.vectispire.common.domain.scans.ScanQueue.leaseUntil;

import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Lapsed;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Policy;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.scanning.AgentClaimLock;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.Scans;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Claiming scans from a queue several instances share.
 *
 * <p><b>One path on every engine, and no row lock.</b> The NestJS version branched on an engine
 * capability — pessimistic locking where available, a conditional take elsewhere — and the
 * campaign showed the branch was buying trouble rather than throughput. See {@code takeBatch}
 * for what each half of it actually cost on MySQL.
 */
@Repository
public class ScanQueue {

    private static final int ERROR_MAX_LENGTH = 2_000;

    private final Scans scans;
    private final AgentClaimLock agents;
    private final Policy policy;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ScanQueue(Scans scans, AgentClaimLock agents, Policy policy, Clock clock, TransactionTemplate transactions) {
        this.scans = scans;
        this.agents = agents;
        this.policy = policy;
        this.clock = clock;
        this.transactions = transactions;
    }

    /**
     * Claims up to {@code limit} pending scans for this worker.
     *
     * <p><b>Deliberately not one transaction, and this is the subtle half.</b> Each take is its
     * own; the candidate reads are outside any. Wrapping the whole claim would be the natural
     * shape and is wrong under <b>REPEATABLE READ</b>, which is MySQL's default: the
     * transaction's snapshot is fixed at its first read, so every retry sees the same five rows
     * a competitor already took, fails to take them, and retries against the same stale view —
     * for ever. The queue stopped draining at five of twenty and no error was raised.
     *
     * <p>PostgreSQL, on READ COMMITTED, gives each statement a fresh snapshot and hid the
     * problem entirely.
     */
    public List<ScanEntity> claim(int limit, String worker, Collection<String> agentLabels) {
        if (limit <= 0) {
            return List.of();
        }

        List<ScanEntity> claimed = new ArrayList<>(limit);
        for (int attempt = 0; attempt < policy.claimAttempts(); attempt++) {
            List<ScanEntity> batch = takeBatch(limit - claimed.size(), worker, agentLabels);
            claimed.addAll(batch);

            if (claimed.size() >= limit) {
                break;
            }
            // Nothing taken: the queue is empty, *everything is locked elsewhere*, or nothing is
            // destined for this agent. Another turn tells the second case from the others, and
            // the loop is bounded.
            if (batch.isEmpty() && countPending() == 0) {
                break;
            }
        }
        return claimed;
    }

    /**
     * Claims one pending scan for a remote agent, <b>unless it already runs {@code limit}</b>.
     *
     * <p><b>The count and the take commit together, behind the agent's own row.</b> Counting,
     * then taking, as two statements is the obvious shape and it is wrong: two polls of the same
     * agent — two processes sharing its key, or two instances of the control plane — both count
     * one running scan under a limit of two, both take, and the agent holds three. Most of the
     * time the two polls happen to read the same oldest candidate and the conditional update that
     * makes {@link #claim} safe turns one of them away; it says nothing when they read
     * <em>different</em> rows — a scan requeued between their reads, one created out of order —
     * and that is rare enough to pass every test that does not force it. So the transaction starts
     * by writing the agent's row, which every engine serializes: PostgreSQL and MySQL hold the row
     * lock until the commit, SQLite takes its write lock on the first write. The second poll waits
     * there, and counts after the first has committed its take.
     *
     * <p><b>The lock is the first statement, and that is what makes the count fresh on MySQL.</b>
     * Under REPEATABLE READ the snapshot is fixed at the transaction's first plain read — here,
     * the count, taken after the lock was granted and therefore after the competitor's commit.
     * A read before the lock would pin a snapshot from before it, and the count would miss the
     * scan the competitor just took — the same trap {@link #claim} documents.
     *
     * <p><b>The candidates are read outside, as in {@link #claim}</b>, and each attempt is a
     * transaction of its own: a candidate read inside would be served from that pinned snapshot on
     * MySQL, and a row another agent took meanwhile would be offered again on every retry.
     *
     * <p><b>A lapsed lease does not count.</b> Its scan is still {@code scanning} until the next
     * reclaim, but the agent that held it has stopped renewing — dead, or cut off — and counting
     * it would leave a restarted agent unable to claim until somebody else's timer ran.
     *
     * @param limit the agent's limit as the queue applies it — see {@code AgentConcurrency}
     */
    public Optional<ScanEntity> claimWithin(UUID agentId, int limit, Collection<String> agentLabels) {
        String worker = agentId.toString();
        if (limit <= 0) {
            return Optional.empty();
        }

        for (int attempt = 0; attempt < policy.claimAttempts(); attempt++) {
            // **Both cheap checks first, unlocked.** A poll re-checks once a second for as long as
            // it waits; taking the agent's row each time would be a write per second per idle agent
            // for an answer these two reads already give. They decide nothing on their own: the
            // count is repeated behind the lock before anything is taken.
            if (countHeld(worker) >= limit) {
                return Optional.empty();
            }
            List<ScanEntity> candidates = candidates(1, agentLabels);
            if (candidates.isEmpty()) {
                return Optional.empty();
            }

            Taken outcome;
            try {
                outcome = transactions.execute(status -> takeWithinLimit(agentId, worker, limit, candidates));
            } catch (DataAccessException | TransactionException contended) {
                // Same event as in `takeBatch`, spelled by the engine rather than by a zero row
                // count — and here it can also surface at the commit, once the conditional update
                // has marked the shared transaction for rollback. Somebody else took the row.
                outcome = Taken.LOST;
            }
            switch (outcome) {
                case Taken.Scan(long id) -> {
                    return scans.findById(id);
                }
                case Taken.Full full -> {
                    return Optional.empty();
                }
                case Taken.Lost lost -> {
                    // Another claimant took the candidate between our read and our update: read
                    // again, outside, and try the next one.
                }
            }
        }
        return Optional.empty();
    }

    /** What one attempt of {@link #claimWithin} came back with. */
    private sealed interface Taken {

        Taken FULL = new Full();
        Taken LOST = new Lost();

        record Scan(long id) implements Taken {}

        /** The agent already runs its limit — counted behind the lock, so this is final. */
        record Full() implements Taken {}

        /** Every candidate was taken by somebody else in the meantime; worth another read. */
        record Lost() implements Taken {}
    }

    private Taken takeWithinLimit(UUID agentId, String worker, int limit, List<ScanEntity> candidates) {
        Instant claimedAt = clock.instant();
        // The lock, and it has to come first — see `claimWithin`. Zero rows means the agent was
        // deleted while it polled: nothing to claim for.
        if (!agents.lockForClaim(agentId, claimedAt)) {
            return Taken.FULL;
        }
        if (scans.countHeld(worker, ScanStatus.SCANNING.wireName(), claimedAt) >= limit) {
            return Taken.FULL;
        }
        Instant leaseUntil = leaseUntil(claimedAt, policy);
        for (ScanEntity candidate : candidates) {
            int affected = scans.take(
                    candidate.getId(),
                    ScanStatus.PENDING.wireName(),
                    ScanStatus.SCANNING.wireName(),
                    worker,
                    claimedAt,
                    leaseUntil);
            if (affected == 1) {
                return new Taken.Scan(candidate.getId());
            }
        }
        return Taken.LOST;
    }

    /**
     * The scans this worker holds and is still renewing.
     *
     * <p>Not {@code countByStatusAndClaimedBy}: that one counts a lapsed lease too, which is a
     * scan nobody is running any more.
     */
    public long countHeld(String worker) {
        return scans.countHeld(worker, ScanStatus.SCANNING.wireName(), clock.instant());
    }

    private List<ScanEntity> candidates(int wanted, Collection<String> agentLabels) {
        return agentLabels.isEmpty()
                ? scans.findClaimableUnlabelled(ScanStatus.PENDING.wireName(), Limit.of(wanted))
                : scans.findClaimable(ScanStatus.PENDING.wireName(), agentLabels, Limit.of(wanted));
    }

    public Optional<ScanEntity> byId(long scanId) {
        return scans.findById(scanId);
    }

    public ScanEntity save(ScanEntity scan) {
        return scans.save(scan);
    }

    /** How many scans are running, from which the remaining capacity is deduced. */
    public long countRunning() {
        return scans.countByStatus(ScanStatus.SCANNING.wireName());
    }

    public long countPending() {
        return scans.countByStatus(ScanStatus.PENDING.wireName());
    }

    /**
     * Holds this worker's scan for the write that records its results, or reports it lost.
     *
     * <p><b>An update, not a read, and inside the writing transaction.</b> It used to be a plain
     * read of the owner: nothing stopped a reclaim and a new take from committing between that
     * read and the final save, which then merged the stale results over the successor's claim.
     * The conditional update takes the row lock and keeps it until the write commits, so a
     * concurrent reclaim waits, then finds the scan no longer lapsed — or no longer running — and
     * changes nothing. If the reclaim got there first, this matches nothing and the results are
     * discarded.
     */
    @Transactional
    public boolean holdForWrite(long scanId, String worker) {
        return renewLease(scanId, worker);
    }

    /** Extends a progressing scan's lease. False when it is no longer this worker's. */
    @Transactional
    public boolean renewLease(long scanId, String worker) {
        Instant until = leaseUntil(clock.instant(), policy);
        return scans.renewLease(scanId, ScanStatus.SCANNING.wireName(), worker, until) > 0;
    }

    /** How long a lease runs before it has to be renewed. */
    public Duration lease() {
        return policy.lease();
    }

    /** Puts this worker's scan back in the queue. False when it was no longer this worker's. */
    @Transactional
    public boolean requeue(long scanId, String worker) {
        return scans.releaseOwned(
                scanId, ScanStatus.SCANNING.wireName(), worker, ScanStatus.PENDING.wireName(), null) > 0;
    }

    /** Ends this worker's scan in failure, lease included. False when it was no longer this worker's. */
    @Transactional
    public boolean fail(long scanId, String worker, String reason) {
        return scans.releaseOwned(
                scanId, ScanStatus.SCANNING.wireName(), worker, ScanStatus.FAILED.wireName(), truncate(reason)) > 0;
    }

    /**
     * Keeps a reason inside the column.
     *
     * <p>A scanner's stack trace runs to tens of kilobytes, and the write that carries it whole
     * fails on the length — turning "the scan failed" into "the scan failed <em>and we could not
     * say so</em>", which leaves the row claimed and the lease running.
     */
    private static String truncate(String reason) {
        if (reason == null) {
            return null;
        }
        return reason.length() <= ERROR_MAX_LENGTH ? reason : reason.substring(0, ERROR_MAX_LENGTH);
    }

    /**
     * What became of the scans whose lease lapsed.
     *
     * @param requeued handed back to the queue; some other worker will take them
     * @param failed out of attempts. A target that jams its worker every time would otherwise
     *     circulate through the whole fleet indefinitely, and the operator would see a scan
     *     forever about to start
     */
    public record Reclaimed(List<Long> requeued, List<Long> failed) {}

    /**
     * Reclaims scans whose worker stopped reporting.
     *
     * <p>A lease lapses when a worker goes quiet: the process died, the machine vanished, the
     * network dropped. <b>Nothing is stopped here</b> — the work may still be running elsewhere,
     * and nothing in this process can kill a thread on another machine. The row simply becomes
     * claimable again, and {@link #holdForWrite} is what will later refuse the deposed worker's
     * results.
     *
     * <p>Filtered in SQL rather than by loading every running scan and comparing in memory: that
     * version worked only while the column was text, and stopped as soon as it became a real
     * timestamp on one engine out of four.
     *
     * <p><b>No transaction around the loop, deliberately.</b> Each release is a conditional update
     * with a transaction of its own, and nothing here needs the set to change atomically: a scan
     * requeued while its neighbour is not is a correct outcome. Wrapping the read and the updates
     * in one transaction broke on SQLite in WAL: the read pins a snapshot, a renewal or a final
     * write commits meanwhile, and the update's upgrade to a write lock is then refused at once
     * with {@code SQLITE_BUSY} — no busy timeout applies to a stale snapshot — instead of waiting
     * and finding the condition false. PostgreSQL and MySQL re-check the condition either way;
     * the nightly's SQLite run was the one that could tell.
     */
    public Reclaimed reclaimLapsedLeases() {
        Instant asOf = clock.instant();
        List<ScanEntity> lapsed = scans.findLapsed(ScanStatus.SCANNING.wireName(), asOf);

        List<Long> requeued = new ArrayList<>();
        List<Long> failed = new ArrayList<>();
        String running = ScanStatus.SCANNING.wireName();
        for (ScanEntity scan : lapsed) {
            // Counted only when the row really changed: the owner may have renewed or finished
            // since it was read, and that scan was not reclaimed.
            if (afterLapse(scan.getAttempts(), policy) == Lapsed.FAIL) {
                if (scans.releaseLapsed(scan.getId(), running, asOf, ScanStatus.FAILED.wireName(), LEASE_EXHAUSTED_MESSAGE) > 0) {
                    failed.add(scan.getId());
                }
            } else if (scans.releaseLapsed(scan.getId(), running, asOf, ScanStatus.PENDING.wireName(), null) > 0) {
                requeued.add(scan.getId());
            }
        }
        return new Reclaimed(List.copyOf(requeued), List.copyOf(failed));
    }

    /**
     * Selects candidates, then takes each with a conditional update.
     *
     * <p><b>No row lock at all, and that is the design rather than a retreat.</b> The
     * conditional update — {@code set status = scanning where id = ? and status = pending} — is
     * already atomic on every engine: two claimants racing on one row both issue it, and exactly
     * one of them changes a row. The lock adds nothing to correctness; it only saves the loser a
     * wasted statement.
     *
     * <p>What it costs is worse than what it saves. {@code SELECT … FOR UPDATE SKIP LOCKED} with
     * an {@code ORDER BY … LIMIT} takes next-key locks on MySQL: the first produced
     * "Deadlock found when trying to get lock" under eight concurrent claimants, and the second
     * counts skipped rows against the {@code LIMIT}, so a claimant whose candidates are all
     * locked comes back empty while rows remain — and the queue stops draining. Both were found
     * by the campaign, on those two engines only.
     *
     * <p>It also removes the capability branch this class used to carry. One path on four
     * engines is one path to reason about.
     */
    private List<ScanEntity> takeBatch(int wanted, String worker, Collection<String> agentLabels) {
        Instant claimedAt = clock.instant();
        Instant leaseUntil = claimedAt.plus(policy.lease());

        List<ScanEntity> candidates = candidates(wanted, agentLabels);

        List<Long> taken = new ArrayList<>(candidates.size());
        for (ScanEntity candidate : candidates) {
            int affected;
            try {
                affected = scans.take(
                        candidate.getId(),
                        ScanStatus.PENDING.wireName(),
                        ScanStatus.SCANNING.wireName(),
                        worker,
                        claimedAt,
                        leaseUntil);
            } catch (DataAccessException contended) {
                // Some engines answer a losing conditional update with "Record has changed since
                // last read" rather than with zero rows affected. Same event, different
                // spelling: somebody else took the row. Treating it as a failure would abort a
                // claim over an outcome the loop already handles.
                affected = 0;
            }
            if (affected == 1) {
                taken.add(candidate.getId());
            }
        }
        // Re-read rather than returned from the candidates: the update went round the
        // persistence context, so those instances still hold the values they had before it.
        return taken.isEmpty() ? List.of() : scans.findAllById(taken);
    }

}
