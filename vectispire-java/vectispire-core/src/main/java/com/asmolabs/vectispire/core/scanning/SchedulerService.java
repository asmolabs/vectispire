package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.scanning.internal.LeaderElection;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.TargetSchedules;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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

    /** What "already under way" means to a round: a scan waiting, or one running. */
    private static final List<String> IN_FLIGHT = List.of(ScanStatus.PENDING.wireName(), ScanStatus.SCANNING.wireName());

    private final TargetCatalog targets;
    private final TargetSchedules schedules;
    private final ScanRepository scans;
    private final LeaderElection election;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public SchedulerService(
            TargetCatalog targets,
            TargetSchedules schedules,
            ScanRepository scans,
            LeaderElection election,
            TransactionTemplate transactions,
            Clock clock) {
        this.targets = targets;
        this.schedules = schedules;
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
        // Read once per tick: a default changed mid-tick must not judge half the estate by each value.
        Duration defaultInterval = schedules.defaultInterval();

        for (RepositoryView repository : targets.repositories()) {
            if (Schedules.isDue(TargetSchedules.of(repository), defaultInterval, at)) {
                queued += queueRepository(repository, at);
            }
        }

        for (ContainerView container : targets.containers()) {
            if (Schedules.isDue(TargetSchedules.of(container), defaultInterval, at)) {
                queued += queueContainer(container, at);
            }
        }

        if (queued > 0) {
            log.info("Scheduler: {} scan(s) queued.", queued);
        }
        return queued;
    }

    private int queueRepository(RepositoryView repository, Instant at) {
        return queue(
                "repository " + repository.id(),
                () -> targets.stampScheduled(new ScanTarget.Repository(repository.id()), at),
                () -> scans.countByStatusInAndRepoId(IN_FLIGHT, repository.id()),
                () -> {
                    ScanEntity scan = newScan(at);
                    scan.setRepoId(repository.id());
                    scan.setBranch(repository.branch());
                    scan.setSubPath(repository.subPath());
                    scan.setRequiredAgentLabel(repository.requiredAgentLabel());
                    return scan;
                });
    }

    private int queueContainer(ContainerView container, Instant at) {
        return queue(
                "container " + container.id(),
                () -> targets.stampScheduled(new ScanTarget.Container(container.id()), at),
                () -> scans.countByStatusInAndContainerId(IN_FLIGHT, container.id()),
                () -> {
                    ScanEntity scan = newScan(at);
                    scan.setContainerId(container.id());
                    // "n/a" rather than empty: the column is mandatory, an image has no branch,
                    // and this is what the manual trigger already writes — a scheduled scan must
                    // be indistinguishable from a manual one downstream.
                    scan.setBranch("n/a");
                    scan.setRequiredAgentLabel(container.requiredAgentLabel());
                    return scan;
                });
    }

    /**
     * Queues a target unless a scan of it is already waiting or running.
     *
     * <p>A target whose previous scan has not started yet does not need a second, and stacking them
     * grows the queue without learning anything. Nor does one whose scan is running: under a weekly
     * default a slow scan of a large repository can still be running when the round comes, and the
     * round would only queue the same examination behind it.
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
}
