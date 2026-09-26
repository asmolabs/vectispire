package com.asmolabs.vectispire.core.maintenance.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask.Cadence;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The periodic housekeeping: three turns, each running the {@link MaintenanceTask}s of its cadence
 * in the order Spring sorted them by their {@code @Order}.
 *
 * <p><b>Every turn waits before its first run.</b> {@code fixedDelay} spaces out the runs that
 * follow and does nothing about the first, which otherwise fires the instant the context is
 * ready — while Flyway has just finished, the pool is still filling, and an instance that is
 * about to lose a startup race for the leader lease is competing for it. Half a minute costs
 * nothing and removes a whole class of "only on the first tick after a deploy".
 *
 * <p><b>No leader election here, deliberately</b> — see {@link MaintenanceTask}: this class may only
 * host work that tolerates being run on several instances at once.
 */
@Component
public class MaintenanceJobs {

    private static final Logger log = LoggerFactory.getLogger(MaintenanceJobs.class);

    private final Map<Cadence, List<MaintenanceTask>> tasks = new EnumMap<>(Cadence.class);

    /**
     * One turn at a time, per cadence.
     *
     * <p>Spring's fixed-delay scheduling already waits for the previous run, but these are also
     * callable directly — from a test, from an operations endpoint — and a slow purge on a
     * long-neglected database must not have the next turn start over the top of it.
     */
    private final Map<Cadence, AtomicBoolean> running = new EnumMap<>(Cadence.class);

    /** @param tasks in the order Spring injects a list: by {@code @Order}, which the hourly turn keeps */
    public MaintenanceJobs(List<MaintenanceTask> tasks) {
        for (Cadence cadence : Cadence.values()) {
            this.tasks.put(cadence, new ArrayList<>());
            running.put(cadence, new AtomicBoolean());
        }
        tasks.forEach(task -> this.tasks.get(task.cadence()).add(task));
    }

    @Scheduled(
            fixedDelayString = "${vectispire.jobs.relay-interval:60s}",
            initialDelayString = "${vectispire.jobs.initial-delay:30s}")
    public void relayNotifications() {
        turn(Cadence.RELAY);
    }

    /** The scan scheduler's tick. Leader-only, which {@code SchedulerService} enforces itself. */
    @Scheduled(
            fixedDelayString = "${vectispire.jobs.scheduler-interval:60s}",
            initialDelayString = "${vectispire.jobs.initial-delay:30s}")
    public void scheduleDueScans() {
        turn(Cadence.SCHEDULING);
    }

    @Scheduled(
            fixedDelayString = "${vectispire.jobs.maintenance-interval:1h}",
            initialDelayString = "${vectispire.jobs.initial-delay:30s}")
    public void hourlyMaintenance() {
        turn(Cadence.HOURLY);
    }

    /**
     * Runs a cadence's tasks unless its turn is already running, and swallows what they throw.
     *
     * <p>Logged and swallowed: a housekeeping failure must not bring down the process serving
     * requests, and an exception escaping a scheduled method stops nothing here but would make
     * the next turn's log unreadable. Each task's own service already decides what a failure
     * costs it. <b>A task that throws ends its turn</b> — the tasks after it wait for the next one,
     * as they did when the turn was a single method; the guard is released either way, so one
     * failing task never silences the tick for ever.
     */
    private void turn(Cadence cadence) {
        AtomicBoolean guard = running.get(cadence);
        if (!guard.compareAndSet(false, true)) {
            return;
        }
        try {
            tasks.get(cadence).forEach(MaintenanceTask::run);
        } catch (RuntimeException failed) {
            log.error("{} failed: {}", cadence.label(), failed.getMessage(), failed);
        } finally {
            guard.set(false);
        }
    }
}
