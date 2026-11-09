package com.asmolabs.vectispire.core.targets.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.targets.TargetDeletionService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The rows a deleted target left behind, swept — last, after every task that could still name them.
 */
@Component
@Order(MaintenanceTask.Sequence.ORPHANED_TARGET_ROWS)
public class OrphanedTargetRowsTask implements MaintenanceTask {

    private final TargetDeletionService deletion;

    public OrphanedTargetRowsTask(TargetDeletionService deletion) {
        this.deletion = deletion;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        deletion.purgeOrphanedTargetData();
    }
}
