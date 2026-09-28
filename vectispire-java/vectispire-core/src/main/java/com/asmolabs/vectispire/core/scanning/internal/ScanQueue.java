package com.asmolabs.vectispire.core.scanning.internal;

import static com.asmolabs.vectispire.common.domain.scans.ScanQueue.LEASE_EXHAUSTED_MESSAGE;
import static com.asmolabs.vectispire.common.domain.scans.ScanQueue.afterFailure;
import static com.asmolabs.vectispire.common.domain.scans.ScanQueue.leaseUntil;

import com.asmolabs.vectispire.common.domain.scans.FailureKind;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Next;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Policy;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.scanning.AgentClaimLock;
import com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
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

    private final ScanRepository scans;
    private final AgentClaimLock agents;
    private final Policy policy;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ScanQueue(ScanRepository scans, AgentClaimLock agents, Policy policy, Clock clock, TransactionTemplate transactions) {
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
            // the loop is bounded. Counted among the scans due: one waiting out its retry delay is
            // no reason to turn again, and every tick of a queue in backoff would otherwise run the
            // whole loop for nothing.
            if (batch.isEmpty() && scans.countDue(ScanStatus.PENDING.wireName(), clock.instant()) == 0) {
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
     * <p><b>An exclusion narrows the selection, never the take.</b> The repositories left out are
     * decided while the candidates are read and not re-checked by the conditional update: a
     * repository given a key between the two is taken all the same, and the caller, which reads the
     * repository again to build the task, is what notices — see {@link #requeueRefunded}.
     *
     * @param limit the agent's limit as the queue applies it — see {@code AgentConcurrency}
     * @param exclusion the repositories whose scans this agent must not take — for an agent that
     *     cannot be handed a delegated credential, those that carry one (decision 0031)
     */
    public AgentClaim claimWithin(UUID agentId, int limit, Collection<String> agentLabels, Exclusion exclusion) {
        String worker = agentId.toString();
        if (limit <= 0) {
            return AgentClaim.NOTHING;
        }

        boolean kept = false;
        for (int attempt = 0; attempt < policy.claimAttempts(); attempt++) {
            // **Both cheap checks first, unlocked.** A poll re-checks once a second for as long as
            // it waits; taking the agent's row each time would be a write per second per idle agent
            // for an answer these two reads already give. They decide nothing on their own: the
            // count is repeated behind the lock before anything is taken.
            if (countHeld(worker) >= limit) {
                return new AgentClaim(Optional.empty(), kept);
            }
            Instant asOf = clock.instant();
            Selection selection = exclusion.excludesNothing()
                    ? new Selection(candidates(1, agentLabels, asOf).stream().map(ScanEntity::getId).toList(), false)
                    : eligible(agentLabels, exclusion, asOf);
            kept |= selection.kept();
            List<Long> candidates = selection.candidates();
            if (candidates.isEmpty()) {
                return new AgentClaim(Optional.empty(), kept);
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
                    return new AgentClaim(scans.findById(id), kept);
                }
                case Taken.Full full -> {
                    return new AgentClaim(Optional.empty(), kept);
                }
                case Taken.Lost lost -> {
                    // Another claimant took the candidate between our read and our update: read
                    // again, outside, and try the next one.
                }
            }
        }
        return new AgentClaim(Optional.empty(), kept);
    }

    /**
     * The repositories an agent must be kept from, asked of whoever knows which carry a credential.
     *
     * <p>Asked a page at a time, never of the whole queue: see {@link #eligible}.
     */
    @FunctionalInterface
    public interface Exclusion {

        /** Nothing left out: the agent can be handed whatever a scan needs, and no page is walked. */
        Exclusion NONE = new Exclusion() {
            @Override
            public Set<Long> among(Set<Long> repositories) {
                return Set.of();
            }

            @Override
            public boolean excludesNothing() {
                return true;
            }
        };

        /** Which of these repositories — at most {@link ScanQueue#PAGE} of them — the agent must not take. */
        Set<Long> among(Set<Long> repositories);

        default boolean excludesNothing() {
            return false;
        }
    }

    /**
     * What {@link #claimWithin} came back with.
     *
     * @param kept whether the exclusion left a scan this agent could otherwise have taken for another
     *     executor — what the caller tells the agent when nothing else was there for it
     */
    public record AgentClaim(Optional<ScanEntity> scan, boolean kept) {

        static final AgentClaim NOTHING = new AgentClaim(Optional.empty(), false);
    }

    /** The candidates an attempt tries, and whether the exclusion skipped any on the way. */
    private record Selection(List<Long> candidates, boolean kept) {}

    /**
     * How many waiting scans one read of {@link #eligible} carries, and so the most repositories an
     * {@link Exclusion} is asked about at once — far below every engine's bind-parameter limit, and
     * a size at which the question costs one indexed read on each side.
     */
    public static final int PAGE = 256;

    /**
     * How many pages one attempt walks before giving up. <b>A cost bound, not a correctness one</b>:
     * past four thousand scans the agent may not take, a scan it may take behind them waits for the
     * queue ahead of it to drain — it is not lost — while a poll that re-checks every second never
     * walks an unbounded queue.
     */
    static final int PAGES = 16;

    /**
     * The first scan in claim order that the exclusion does not keep from this agent.
     *
     * <p><b>Walked a page at a time instead of excluding a list</b>, which the selection used to
     * carry as {@code not in :excluded}: one bind parameter per waiting repository that carries a
     * credential, bounded only by the queue, and past the engines' limits — 65,535 parameters for the
     * PostgreSQL driver and a MySQL server-side statement, 32,766 in SQLite's default build — a claim
     * that failed on every poll. Each page is read in the claim's own order, from where the last one
     * ended, and only its repositories are asked about, so no statement here or in the exclusion's
     * owner carries more than {@link #PAGE}, however large the queue.
     */
    private Selection eligible(Collection<String> agentLabels, Exclusion exclusion, Instant asOf) {
        String pending = ScanStatus.PENDING.wireName();
        boolean kept = false;
        ClaimCandidate last = null;
        for (int page = 0; page < PAGES; page++) {
            List<ClaimCandidate> rows = page(pending, agentLabels, asOf, last);
            Set<Long> repositories = rows.stream()
                    .map(ClaimCandidate::repoId)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
            Set<Long> excluded = repositories.isEmpty() ? Set.of() : exclusion.among(repositories);
            for (ClaimCandidate row : rows) {
                // An image scan, or a repository with no key and no token, stays the agent's to take.
                if (row.repoId() == null || !excluded.contains(row.repoId())) {
                    return new Selection(List.of(row.id()), kept);
                }
                kept = true;
            }
            if (rows.size() < PAGE) {
                break;
            }
            last = rows.getLast();
        }
        return new Selection(List.of(), kept);
    }

    private List<ClaimCandidate> page(String pending, Collection<String> agentLabels, Instant asOf, ClaimCandidate after) {
        Limit page = Limit.of(PAGE);
        if (after == null) {
            return agentLabels.isEmpty()
                    ? scans.findClaimableUnlabelledPage(pending, asOf, page)
                    : scans.findClaimablePage(pending, agentLabels, asOf, page);
        }
        return agentLabels.isEmpty()
                ? scans.findClaimableUnlabelledPageAfter(pending, asOf, after.createdAt(), after.id(), page)
                : scans.findClaimablePageAfter(pending, agentLabels, asOf, after.createdAt(), after.id(), page);
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

    private Taken takeWithinLimit(UUID agentId, String worker, int limit, List<Long> candidates) {
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
        for (long candidate : candidates) {
            int affected = scans.take(
                    candidate,
                    ScanStatus.PENDING.wireName(),
                    ScanStatus.SCANNING.wireName(),
                    worker,
                    claimedAt,
                    leaseUntil);
            if (affected == 1) {
                return new Taken.Scan(candidate);
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

    private List<ScanEntity> candidates(int wanted, Collection<String> agentLabels, Instant asOf) {
        String pending = ScanStatus.PENDING.wireName();
        return agentLabels.isEmpty()
                ? scans.findClaimableUnlabelled(pending, asOf, Limit.of(wanted))
                : scans.findClaimable(pending, agentLabels, asOf, Limit.of(wanted));
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

    /** How many scans wait, those serving out a retry delay included — what the queue gauge shows. */
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

    /**
     * Puts this worker's scan back in the queue <b>and refunds the attempt its claim counted</b>.
     * False when it was no longer this worker's.
     *
     * <p>Only for a claim that could never have been honoured, on a path that cannot repeat for the
     * same scan and executor: a delegated credential withheld from an agent whose selection excluded
     * the repositories carrying one, when the repository gained its key between the selection and the
     * delivery. The next selection excludes it, so the refund is paid once. Anywhere else, a refund
     * turns a scan that keeps going undelivered into one that circulates for ever — which is why
     * {@link #requeue} does not refund.
     */
    @Transactional
    public boolean requeueRefunded(long scanId, String worker) {
        return scans.releaseOwnedRefunded(
                scanId, ScanStatus.SCANNING.wireName(), worker, ScanStatus.PENDING.wireName()) > 0;
    }

    /**
     * What became of an attempt its executor could not run.
     *
     * @param next back in the queue from an instant, or failed for good — permanently, or at the limit
     * @param attempt the attempt that failed, counted from one
     */
    public record Abandoned(Next next, int attempt, int maxAttempts) {

        public boolean retried() {
            return next instanceof Next.Retry;
        }

        /** When the scan can be claimed again; empty when it failed for good. */
        public Optional<Instant> notBefore() {
            return next instanceof Next.Retry(Instant at) ? Optional.of(at) : Optional.empty();
        }

        /** Failed for good because another attempt would meet the same refusal, not because the attempts ran out. */
        public boolean permanent() {
            return next instanceof Next.Fail(boolean permanent) && permanent;
        }
    }

    /**
     * Ends one attempt of this worker's scan that could not run, <b>whichever executor it was</b>:
     * failed for good if the failure is permanent or the attempt the last, otherwise back in the
     * queue with the attempt counted and a wait before the next claim —
     * {@link com.asmolabs.vectispire.common.domain.scans.ScanQueue#afterFailure}, the one rule for an
     * agent's report, the built-in worker's own failure and, through the reclaim, a lapsed lease. The
     * reason is stored either way, so a scan waiting for its next attempt says why the last one did
     * not run.
     *
     * <p><b>The built-in worker used to fail for good at its first error</b>, through a {@code fail}
     * that took no attempt into account: a clone refused by a network blip failed the scan on the
     * control plane where the same blip on an agent cost one attempt of three. A scan's fate no longer
     * depends on which executor took it, and that method is gone.
     *
     * @param attempt the attempt the failure is about, as the claim handed it to the executor
     * @param kind the executor's word on whether another attempt could pass — see {@link FailureKind}
     * @param reason the sentence stored on the scan, given what became of it
     * @return empty when the scan is no longer this worker's, or no longer at that attempt — a report
     *     already applied, or one about an attempt since superseded; nothing is written then
     */
    public Optional<Abandoned> abandon(
            long scanId,
            String worker,
            int attempt,
            FailureKind kind,
            java.util.function.Function<Abandoned, String> reason) {
        Optional<ScanEntity> held = scans.findById(scanId)
                .filter(scan -> ScanStatus.SCANNING.wireName().equals(scan.getStatus()))
                .filter(scan -> worker.equals(scan.getClaimedBy()))
                .filter(scan -> scan.getAttempts() == attempt);
        if (held.isEmpty()) {
            return Optional.empty();
        }
        Abandoned abandoned = new Abandoned(afterFailure(attempt, kind, clock.instant(), policy), attempt, policy.maxAttempts());
        String to = abandoned.retried() ? ScanStatus.PENDING.wireName() : ScanStatus.FAILED.wireName();
        // The condition read above is repeated by the statement: between the two, the lease may have
        // lapsed and the reclaim run, and the scan be taken again — by this very agent.
        int changed = scans.releaseOwnedAttempt(
                scanId,
                ScanStatus.SCANNING.wireName(),
                worker,
                attempt,
                to,
                truncate(reason.apply(abandoned)),
                abandoned.notBefore().orElse(null));
        return changed > 0 ? Optional.of(abandoned) : Optional.empty();
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
            // since it was read, and that scan was not reclaimed. A lapse is a transient failure
            // nobody reported — the worker went quiet — and it waits as a reported one does: a
            // worker that dies on a target every time would otherwise hand it to the next claimant
            // at once, and the fleet would spend the attempts in as many ticks.
            switch (afterFailure(scan.getAttempts(), FailureKind.TRANSIENT, asOf, policy)) {
                case Next.Fail fail -> {
                    if (scans.releaseLapsed(
                                    scan.getId(), running, asOf, ScanStatus.FAILED.wireName(), LEASE_EXHAUSTED_MESSAGE, null)
                            > 0) {
                        failed.add(scan.getId());
                    }
                }
                case Next.Retry retry -> {
                    if (scans.releaseLapsed(
                                    scan.getId(), running, asOf, ScanStatus.PENDING.wireName(), null, retry.notBefore())
                            > 0) {
                        requeued.add(scan.getId());
                    }
                }
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

        List<ScanEntity> candidates = candidates(wanted, agentLabels, claimedAt);

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
