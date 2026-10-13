package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.core.forges.ForgeTokenWatch;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The forge connections' token expiries, compared with the clock every hour and announced once per change — the
 * forges' twin of the tracker token's check, placed beside it.
 *
 * <p>Hourly, because what moves is the date and not the forge: a token enters its fourteen days, or lapses, at an
 * hour nobody chose, and the announcement follows within the hour. Every instance runs it; the conditional update in
 * {@link ForgeTokenWatch} lets one of them announce each change.
 */
@Component
@Order(MaintenanceTask.Sequence.FORGE_TOKEN_WATCH)
public class ForgeTokenWatchTask implements MaintenanceTask {

    private final ForgeTokenWatch watch;

    public ForgeTokenWatchTask(ForgeTokenWatch watch) {
        this.watch = watch;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        watch.watch();
    }
}
