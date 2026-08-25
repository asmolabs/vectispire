package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The periodic housekeeping.
 *
 * <p><b>Hourly, not on every scheduler tick.</b> The purge walks every scan carrying a payload;
 * running it every fifteen seconds would cost a pointless query each time for a result that
 * only changes at the rate scans happen.
 *
 * <p><b>Every job waits before its first run.</b> {@code fixedDelay} spaces out the runs that
 * follow and does nothing about the first, which otherwise fires the instant the context is
 * ready — while Flyway has just finished, the pool is still filling, and an instance that is
 * about to lose a startup race for the leader lease is competing for it. Half a minute costs
 * nothing and removes a whole class of "only on the first tick after a deploy".
 *
 * <p><b>No leader election here, deliberately.</b> Everything below is idempotent: dropping the
 * same payload twice costs nothing, and the ticket sweep deduplicates on the reference stored
 * on the issue. That is not true of every periodic job — scheduling scans does need an election
 * — so this class may only host work that tolerates being run twice.
 */
@Component
public class MaintenanceJobs {

    private static final Logger log = LoggerFactory.getLogger(MaintenanceJobs.class);

    private final RetentionService retention;
    private final OutboxService outbox;
    private final TicketSweepService tickets;
    private final SessionCleanupService sessions;
    private final InventoryBackfill backfill;
    private final SchedulerService scheduler;
    private final IssueTriageService triage;
    private final PostureDigestService digest;
    private final TargetDeletionService targetDeletion;

    /**
     * One turn at a time, per job.
     *
     * <p>Spring's fixed-delay scheduling already waits for the previous run, but these are also
     * callable directly — from a test, from an operations endpoint — and a slow purge on a
     * long-neglected database must not have the next turn start over the top of it.
     */
    private final AtomicBoolean maintaining = new AtomicBoolean();

    private final AtomicBoolean relaying = new AtomicBoolean();
    private final AtomicBoolean dispatching = new AtomicBoolean();

    public MaintenanceJobs(
            RetentionService retention,
            OutboxService outbox,
            TicketSweepService tickets,
            SessionCleanupService sessions,
            InventoryBackfill backfill,
            SchedulerService scheduler,
            IssueTriageService triage,
            PostureDigestService digest,
            TargetDeletionService targetDeletion) {
        this.retention = retention;
        this.outbox = outbox;
        this.tickets = tickets;
        this.sessions = sessions;
        this.backfill = backfill;
        this.scheduler = scheduler;
        this.triage = triage;
        this.digest = digest;
        this.targetDeletion = targetDeletion;
    }

    /**
     * The notification relay, more frequent than the purge.
     *
     * <p>One minute: it is the shortest retry delay in the backoff policy, so a slower turn
     * would make a due message wait longer than intended, and a faster one would find nothing
     * to do.
     */
    @Scheduled(
            fixedDelayString = "${vectispire.jobs.relay-interval:60s}",
            initialDelayString = "${vectispire.jobs.initial-delay:30s}")
    public void relayNotifications() {
        run(relaying, "notification relay", () -> outbox.relay(OutboxRetry.MAX_PER_PASS));
    }

    /** The scan scheduler's tick. Leader-only, which {@code SchedulerService} enforces itself. */
    @Scheduled(
            fixedDelayString = "${vectispire.jobs.scheduler-interval:60s}",
            initialDelayString = "${vectispire.jobs.initial-delay:30s}")
    public void scheduleDueScans() {
        run(dispatching, "scheduling tick", scheduler::runOnce);
    }

    @Scheduled(
            fixedDelayString = "${vectispire.jobs.maintenance-interval:1h}",
            initialDelayString = "${vectispire.jobs.initial-delay:30s}")
    public void hourlyMaintenance() {
        run(maintaining, "maintenance", () -> {
            int pruned = retention.prune();
            if (pruned > 0) {
                log.info("Maintenance: {} scan(s) lightened.", pruned);
            }

            // Purged here rather than in the relay: the table is written on every scan, but the
            // cleanup has no reason to run every minute.
            int delivered = outbox.pruneSent();
            if (delivered > 0) {
                log.info("Maintenance: {} delivered notification(s) purged.", delivered);
            }

            // The ticket sweep runs here and not every minute: it is idempotent — the reference
            // set on the issue is its deduplication key — so a tracker under maintenance is
            // simply retried next turn.
            tickets.sweep();

            // A batch per tick, not the whole history: the inventory of past scans is read back
            // from SBOMs already on disk, and a single pass over ten thousand of them would hold
            // one transaction open for minutes. It converges, and a fresh install has nothing to
            // do here.
            backfill.runOnce();

            // **Nothing called this until now, and that is what the feature was missing.** An
            // acceptance could be recorded "for thirty days", the review date was stored, the
            // SARIF document said "to review on …" — and it never came back, because
            // `expireStale` was reachable only from its own tests. Its javadoc said it was called
            // from this tick, which was the only place the claim existed.
            //
            // Here rather than on page load, for the reason that javadoc gives: a dismissal that
            // lapses overnight has to stop dismissing in the VEX document a customer downloads
            // and in the verdict a pipeline asks for at three in the morning. Hourly, so the
            // worst case is that an acceptance outlives its date by an hour.
            List<Long> expired = triage.expireStale();
            if (!expired.isEmpty()) {
                log.info("Maintenance: {} triage decision(s) returned under review.", expired.size());
            }

            // **Called from here, and asserted at this level.** A weekly report needs no queue —
            // it is derived from the database, so a failed send is simply recomputed next turn —
            // which means this call is the only thing that makes the feature exist. That is
            // exactly the shape `expireStale` had when its javadoc claimed this tick ran it and
            // nothing did.
            //
            // Hourly for a weekly job: the digest decides for itself whether one has gone out
            // since Monday, so the tick only has to be more frequent than the period.
            digest.runOnce();

            SessionCleanupService.CleanupResult cleaned = sessions.prune();
            if (cleaned.sessions() > 0 || cleaned.attempts() > 0) {
                log.info(
                        "Maintenance: {} expired session(s) and {} old login attempt(s) removed.",
                        cleaned.sessions(),
                        cleaned.attempts());
            }

            targetDeletion.purgeOrphanedTargetData();
            return null;
        });
    }

    /**
     * Runs a job unless it is already running, and swallows what it throws.
     *
     * <p>Logged and swallowed: a housekeeping failure must not bring down the process serving
     * requests, and an exception escaping a scheduled method stops nothing here but would make
     * the next turn's log unreadable. Each job's own service already decides what a failure
     * costs it.
     */
    private void run(AtomicBoolean guard, String label, java.util.function.Supplier<?> job) {
        if (!guard.compareAndSet(false, true)) {
            return;
        }
        try {
            job.get();
        } catch (RuntimeException failed) {
            log.error("{} failed: {}", label, failed.getMessage(), failed);
        } finally {
            guard.set(false);
        }
    }
}
