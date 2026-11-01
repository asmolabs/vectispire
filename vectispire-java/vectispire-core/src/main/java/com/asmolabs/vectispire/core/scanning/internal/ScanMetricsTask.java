package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The queue's gauges, read on the scheduler's minute so that a scrape never queries — see {@link
 * PlatformMetrics}. Every instance runs it, as every task: each instance's gauges are its own.
 */
@Component
@Order(MaintenanceTask.Sequence.SCAN_METRICS)
public class ScanMetricsTask implements MaintenanceTask {

    private final PlatformMetrics metrics;

    public ScanMetricsTask(PlatformMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public Cadence cadence() {
        return Cadence.SCHEDULING;
    }

    @Override
    public void run() {
        metrics.refresh();
    }
}
