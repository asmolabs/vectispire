package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules.Schedulable;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The periodic rescan.
 *
 * <p><b>This is the loop that gives the rest of the product its point.</b> A weekly manual scan
 * is not posture management, in a tool whose premise is that new vulnerabilities appear in
 * unchanged code.
 *
 * <p><b>A scheduled scan and a manual scan are indistinguishable downstream</b>: both put a row
 * in the queue, the same worker claims it and the same ingestor handles it. No second code path
 * to keep in step.
 *
 * <p><b>{@code lastScheduledScanAt} is stamped <em>before</em> queueing.</b> Stamping it after
 * would re-trigger the same target on the next tick every time a scan outlasts an interval.
 *
 * <p><b>Leader-only.</b> Stamping before sending protects against one process ticking twice,
 * and not at all against two processes ticking together: with no election, every target would
 * be scanned once per instance. The built-in worker stays per instance — a fleet whose members
 * only claimed work while holding the lease would sit idle behind whichever one holds it.
 */
@Service
public class SchedulerService {

    private static final Logger log = LoggerFactory.getLogger(SchedulerService.class);

    private final GitRepositories repositories;
    private final Containers containers;
    private final Scans scans;
    private final LeaderElection election;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public SchedulerService(
            GitRepositories repositories,
            Containers containers,
            Scans scans,
            LeaderElection election,
            TransactionTemplate transactions,
            Clock clock) {
        this.repositories = repositories;
        this.containers = containers;
        this.scans = scans;
        this.election = election;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** One tick. Returns how many scans were queued. */
    public int runOnce() {
        return runOnce(clock.instant());
    }

    /**
     * @param at <b>the same instant as the due check.</b> Taking the lease at {@code now()} while
     *     targets are judged at {@code at} is two clocks in one tick: one decides who writes, the
     *     other decides what, and nothing guarantees they agree
     */
    public int runOnce(Instant at) {
        if (!holdLeadership(at)) {
            return 0;
        }

        int queued = 0;

        for (RepositoryEntity repository : repositories.findAll()) {
            if (Schedules.isDue(schedulable(repository.getScanCron(), repository.getScanIntervalMinutes(),
                    repository.getLastScheduledScanAt()), at)) {
                queued += queueRepository(repository, at);
            }
        }

        for (ContainerEntity container : containers.findAll()) {
            if (Schedules.isDue(schedulable(container.getScanCron(), container.getScanIntervalMinutes(),
                    container.getLastScheduledScanAt()), at)) {
                queued += queueContainer(container, at);
            }
        }

        if (queued > 0) {
            log.info("Scheduler: {} scan(s) queued.", queued);
        }
        return queued;
    }

    private int queueRepository(RepositoryEntity repository, Instant at) {
        return queue(
                "repository " + repository.getId(),
                () -> repositories.stampScheduled(repository.getId(), at),
                () -> scans.countByStatusAndRepoId(ScanStatus.PENDING.wireName(), repository.getId()),
                () -> {
                    ScanEntity scan = newScan(at);
                    scan.setRepoId(repository.getId());
                    scan.setBranch(repository.getBranch());
                    scan.setSubPath(repository.getSubPath());
                    scan.setRequiredAgentLabel(repository.getRequiredAgentLabel());
                    return scan;
                });
    }

    private int queueContainer(ContainerEntity container, Instant at) {
        return queue(
                "container " + container.getId(),
                () -> containers.stampScheduled(container.getId(), at),
                () -> scans.countByStatusAndContainerId(ScanStatus.PENDING.wireName(), container.getId()),
                () -> {
                    ScanEntity scan = newScan(at);
                    scan.setContainerId(container.getId());
                    // "n/a" rather than empty: the column is mandatory, an image has no branch,
                    // and this is what the manual trigger already writes — a scheduled scan must
                    // be indistinguishable from a manual one downstream.
                    scan.setBranch("n/a");
                    scan.setRequiredAgentLabel(container.getRequiredAgentLabel());
                    return scan;
                });
    }

    /**
     * Queues a target unless it is already waiting.
     *
     * <p>The duplicate is dropped here as it is at the screen's button: a target whose previous
     * scan has not started yet does not need a second, and stacking them grows the queue without
     * learning anything.
     */
    private int queue(String label, Runnable stamp, LongSupplier alreadyQueued, Supplier<ScanEntity> build) {
        try {
            return Optional.ofNullable(transactions.execute(status -> {
                        // Stamped first, including when the queue is already served: without it, a
                        // target whose scan is dragging would be reconsidered on every tick.
                        stamp.run();
                        if (alreadyQueued.getAsLong() > 0) {
                            return 0;
                        }
                        scans.save(build.get());
                        return 1;
                    }))
                    .orElse(0);
        } catch (RuntimeException error) {
            // One failing target must not take the others with it: the next tick will see it
            // again, and the healthy targets will have been served in the meantime.
            log.error("Could not queue {}: {}", label, error.getMessage());
            return 0;
        }
    }

    /**
     * Takes or renews the lease, and <b>fails closed</b>.
     *
     * <p>An instance that cannot reach the lease table is not entitled to assume it is alone.
     * Skipping a tick costs a minute of latency; wrongly believing itself leader costs a
     * duplicate scan of every due target.
     */
    private boolean holdLeadership(Instant at) {
        try {
            return election.acquire(LeaderElection.JOB_SCHEDULER, LeaderElection.INSTANCE_ID, at);
        } catch (RuntimeException unreachable) {
            log.warn("Scheduling lease unreachable — tick skipped: {}", unreachable.getMessage());
            return false;
        }
    }

    private ScanEntity newScan(Instant at) {
        ScanEntity scan = new ScanEntity();
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(at);
        return scan;
    }

    private static Schedulable schedulable(String cron, Integer intervalMinutes, Instant lastScheduledAt) {
        return new Schedulable(
                CronExpressions.parse(cron),
                intervalMinutes == null ? Duration.ZERO : Duration.ofMinutes(intervalMinutes),
                lastScheduledAt);
    }
}
