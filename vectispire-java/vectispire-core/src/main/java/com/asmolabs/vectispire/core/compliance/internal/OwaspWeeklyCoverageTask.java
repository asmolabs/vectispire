package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.core.compliance.OwaspWeeklyCoverageService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The current week's OWASP record, offered on every hourly turn and written when it is six hours old.
 *
 * <p><b>Hourly, and gated by the service.</b> The gate is the age of the week's newest row, read from
 * the database, so it holds across restarts and across instances; a cadence of its own would hold for
 * neither. After the triage expiry, like the compliance capture: an acceptance that lapsed this turn
 * is not recorded as settled.
 */
@Component
@Order(MaintenanceTask.Sequence.OWASP_WEEKLY_COVERAGE)
public class OwaspWeeklyCoverageTask implements MaintenanceTask {

    private final OwaspWeeklyCoverageService weekly;

    public OwaspWeeklyCoverageTask(OwaspWeeklyCoverageService weekly) {
        this.weekly = weekly;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        weekly.capture();
    }
}
