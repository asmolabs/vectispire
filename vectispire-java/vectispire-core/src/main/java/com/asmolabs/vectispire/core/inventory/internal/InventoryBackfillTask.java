package com.asmolabs.vectispire.core.inventory.internal;

import com.asmolabs.vectispire.core.inventory.InventoryBackfill;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The components inventory of past scans, a batch per turn.
 *
 * <p>Not the whole history at once: the inventory is read back from SBOMs already on disk, and a
 * single pass over ten thousand of them would hold one transaction open for minutes. It converges,
 * and a fresh install has nothing to do here.
 */
@Component
@Order(MaintenanceTask.Sequence.INVENTORY_BACKFILL)
public class InventoryBackfillTask implements MaintenanceTask {

    private final InventoryBackfill backfill;

    public InventoryBackfillTask(InventoryBackfill backfill) {
        this.backfill = backfill;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        backfill.runOnce();
    }
}
