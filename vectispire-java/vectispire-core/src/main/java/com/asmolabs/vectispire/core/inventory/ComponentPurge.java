package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.core.inventory.persistence.Components;
import com.asmolabs.vectispire.core.scanning.PurgedScans;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.List;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The components a purged target's scans inventoried, before the scans.
 *
 * <p>The API endpoints and contracts are left to the schema's cascade from the scan and the
 * repository, as they always were. Synchronous and in the deleting transaction, like every {@link
 * TargetPurge} listener.
 */
@Component
class ComponentPurge {

    private final PurgedScans scans;
    private final Components components;

    ComponentPurge(PurgedScans scans, Components components) {
        this.scans = scans;
        this.components = components;
    }

    @EventListener
    @Order(TargetPurge.Phase.SCAN_CHILDREN)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetPurge purge) {
        List<Long> scanIds = scans.idsOf(purge);
        if (!scanIds.isEmpty()) {
            components.deleteByScanIdIn(scanIds);
        }
    }
}
