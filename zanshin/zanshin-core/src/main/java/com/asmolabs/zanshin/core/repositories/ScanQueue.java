package com.asmolabs.zanshin.core.repositories;

import static com.asmolabs.zanshin.common.domain.scans.ScanQueue.LEASE_EXHAUSTED_MESSAGE;
import static com.asmolabs.zanshin.common.domain.scans.ScanQueue.afterLapse;
import static com.asmolabs.zanshin.common.domain.scans.ScanQueue.leaseUntil;

import com.asmolabs.zanshin.common.domain.scans.ScanQueue.Lapsed;
import com.asmolabs.zanshin.common.domain.scans.ScanQueue.Policy;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Claiming scans from a queue several instances share.
 *
 * <p><b>One path on four engines, and no row lock.</b> The NestJS version branched on an engine
 * capability — pessimistic locking where available, a conditional take elsewhere — and the
 * campaign showed the branch was buying trouble rather than throughput. See {@code takeBatch}
 * for what each half of it actually cost on MySQL and MariaDB.
 */
@Repository
public class ScanQueue {

    private static final int ERROR_MAX_LENGTH = 2_000;

    private final ScanRepository scans;
    private final Policy policy;
    private final Clock clock;

    public ScanQueue(ScanRepository scans, Policy policy, Clock clock) {
        this.scans = scans;
        this.policy = policy;
        this.clock = clock;
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
     * Does this worker still hold this scan?
     *
     * <p>Asked <b>inside the writing transaction</b>, never before it. A worker whose lease
     * lapsed while it was scanning has had its scan taken over, and writing its results would
     * overwrite the successor's work with stale ones — which looks like a scan that ran
     * backwards, with no error anywhere.
     */
    @Transactional(readOnly = true)
    public boolean stillOwned(long scanId, String worker) {
        return scans.findById(scanId)
                .filter(scan -> ScanStatus.SCANNING.wireName().equals(scan.getStatus()))
                .filter(scan -> worker.equals(scan.getClaimedBy()))
                .isPresent();
    }

    /** Extends a progressing scan's lease. False when it is no longer this worker's. */
    @Transactional
    public boolean renewLease(long scanId, String worker) {
        Instant until = leaseUntil(clock.instant(), policy);
        return scans.renewLease(scanId, ScanStatus.SCANNING.wireName(), worker, until) > 0;
    }

    /** Puts a scan back in the queue, available to anybody. */
    @Transactional
    public void requeue(long scanId) {
        scans.release(scanId, ScanStatus.PENDING.wireName(), null);
    }

    /** Ends a scan in failure, and drops its lease with it. */
    @Transactional
    public void fail(long scanId, String reason) {
        scans.release(scanId, ScanStatus.FAILED.wireName(), truncate(reason));
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
     * claimable again, and {@link #stillOwned} is what will later refuse the deposed worker's
     * results.
     *
     * <p>Filtered in SQL rather than by loading every running scan and comparing in memory: that
     * version worked only while the column was text, and stopped as soon as it became a real
     * timestamp on one engine out of four.
     */
    @Transactional
    public Reclaimed reclaimLapsedLeases() {
        Instant asOf = clock.instant();
        List<ScanEntity> lapsed = scans.findLapsed(ScanStatus.SCANNING.wireName(), asOf);

        List<Long> requeued = new ArrayList<>();
        List<Long> failed = new ArrayList<>();
        for (ScanEntity scan : lapsed) {
            if (afterLapse(scan.getAttempts(), policy) == Lapsed.FAIL) {
                scans.release(
                        scan.getId(), ScanStatus.FAILED.wireName(), LEASE_EXHAUSTED_MESSAGE);
                failed.add(scan.getId());
            } else {
                scans.release(scan.getId(), ScanStatus.PENDING.wireName(), null);
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
     * an {@code ORDER BY … LIMIT} takes next-key locks on MySQL and MariaDB: the first produced
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

        List<ScanEntity> candidates = agentLabels.isEmpty()
                ? scans.findClaimableUnlabelled(ScanStatus.PENDING.wireName(), Limit.of(wanted))
                : scans.findClaimable(ScanStatus.PENDING.wireName(), agentLabels, Limit.of(wanted));

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
                // MariaDB answers a losing conditional update with "Record has changed since
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
