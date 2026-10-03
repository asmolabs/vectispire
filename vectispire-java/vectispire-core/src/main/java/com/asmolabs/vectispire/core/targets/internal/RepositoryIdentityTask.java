package com.asmolabs.vectispire.core.targets.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.targets.RepositoryIdentityService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The repository rows without their identity, keyed — the rows V73 found, and those an instance of the
 * previous version writes during a rolling upgrade. Until a row is keyed, a second filing of its target
 * is not refused.
 */
@Component
@Order(MaintenanceTask.Sequence.REPOSITORY_IDENTITIES)
public class RepositoryIdentityTask implements MaintenanceTask {

    private final RepositoryIdentityService identities;

    public RepositoryIdentityTask(RepositoryIdentityService identities) {
        this.identities = identities;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        identities.keyUnkeyed();
    }
}
