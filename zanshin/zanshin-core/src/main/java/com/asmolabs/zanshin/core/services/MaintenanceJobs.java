package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.notifications.OutboxRetry;
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
 * ready — while Liquibase has just finished, the pool is still filling, and an instance that is
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
    private final SchedulerService scheduler;

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
            SchedulerService scheduler) {
        this.retention = retention;
        this.outbox = outbox;
        this.tickets = tickets;
        this.sessions = sessions;
        this.scheduler = scheduler;
    }

    /**
     * The notification relay, more frequent than the purge.
     *
     * <p>One minute: it is the shortest retry delay in the backoff policy, so a slower turn
     * would make a due message wait longer than intended, and a faster one would find nothing
     * to do.
     */
    @Scheduled(
            fixedDelayString = "${zanshin.jobs.relay-interval:60s}",
            initialDelayString = "${zanshin.jobs.initial-delay:30s}")
    public void relayNotifications() {
        run(relaying, "notification relay", () -> outbox.relay(OutboxRetry.MAX_PER_PASS));
    }

    /** The scan scheduler's tick. Leader-only, which {@code SchedulerService} enforces itself. */
    @Scheduled(
            fixedDelayString = "${zanshin.jobs.scheduler-interval:60s}",
            initialDelayString = "${zanshin.jobs.initial-delay:30s}")
    public void scheduleDueScans() {
        run(dispatching, "scheduling tick", scheduler::runOnce);
    }

    @Scheduled(
            fixedDelayString = "${zanshin.jobs.maintenance-interval:1h}",
            initialDelayString = "${zanshin.jobs.initial-delay:30s}")
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

            SessionCleanupService.CleanupResult cleaned = sessions.prune();
            if (cleaned.sessions() > 0 || cleaned.attempts() > 0) {
                log.info(
                        "Maintenance: {} expired session(s) and {} old login attempt(s) removed.",
                        cleaned.sessions(),
                        cleaned.attempts());
            }
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
