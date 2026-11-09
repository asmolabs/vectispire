package com.asmolabs.vectispire.core.issues.internal;

import com.asmolabs.vectispire.core.issues.SlaBreachSignals;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The remediation deadlines passed since the last turn, told to the SOC.
 *
 * <p>Hourly, and right after the triage expiry: an acceptance that lapsed this turn puts its issue
 * back among the undecided, and if its deadline passed in the week it is announced now rather than
 * an hour later. A breach is reported at worst an hour after it happened, stamped with the moment it
 * did.
 */
@Component
@Order(MaintenanceTask.Sequence.SLA_BREACHES)
public class SlaBreachTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(SlaBreachTask.class);

    private final SlaBreachSignals breaches;

    public SlaBreachTask(SlaBreachSignals breaches) {
        this.breaches = breaches;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        int signalled = breaches.signalCrossings();
        if (signalled > 0) {
            log.info("Maintenance: {} remediation deadline(s) passed and announced.", signalled);
        }
    }
}
