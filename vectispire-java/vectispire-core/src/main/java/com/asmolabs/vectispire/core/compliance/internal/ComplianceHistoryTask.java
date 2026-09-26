package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.core.compliance.ComplianceHistoryService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The current month's compliance snapshot, rewritten on every turn.
 *
 * <p><b>Written on every pass, not once a month.</b> The capture rewrites the current month's row, so
 * that a closed month carries its end-of-month state rather than the state on the first. A monthly
 * trigger would give the opposite, and nobody expects "August" to mean 1 August.
 */
@Component
@Order(MaintenanceTask.Sequence.COMPLIANCE_HISTORY)
public class ComplianceHistoryTask implements MaintenanceTask {

    private final ComplianceHistoryService history;

    public ComplianceHistoryTask(ComplianceHistoryService history) {
        this.history = history;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        history.capture();
    }
}
