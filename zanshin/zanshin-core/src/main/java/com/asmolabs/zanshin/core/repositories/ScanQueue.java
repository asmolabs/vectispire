package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.common.domain.scans.ScanQueue.Policy;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Repository;

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
            if (batch.isEmpty() && scans.countByStatus(ScanStatus.PENDING.wireName()) == 0) {
                break;
            }
        }
        return claimed;
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
