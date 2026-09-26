package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.scanning.SchedulerService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The scan scheduler's tick, every minute.
 *
 * <p>On every instance, and that is safe: only the leader schedules, which {@code SchedulerService}
 * enforces itself with its lease.
 */
@Component
@Order(MaintenanceTask.Sequence.SCHEDULING_TICK)
public class SchedulingTickTask implements MaintenanceTask {

    private final SchedulerService scheduler;

    public SchedulingTickTask(SchedulerService scheduler) {
        this.scheduler = scheduler;
    }

    @Override
    public Cadence cadence() {
        return Cadence.SCHEDULING;
    }

    @Override
    public void run() {
        scheduler.runOnce();
    }
}
