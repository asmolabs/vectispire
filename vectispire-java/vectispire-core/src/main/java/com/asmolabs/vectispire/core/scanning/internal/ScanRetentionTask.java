package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.scanning.RetentionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The scans' payloads lightened past their retention, hourly.
 */
@Component
@Order(MaintenanceTask.Sequence.SCAN_RETENTION)
public class ScanRetentionTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(ScanRetentionTask.class);

    private final RetentionService retention;

    public ScanRetentionTask(RetentionService retention) {
        this.retention = retention;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        int pruned = retention.prune();
        if (pruned > 0) {
            log.info("Maintenance: {} scan(s) lightened.", pruned);
        }
    }
}
