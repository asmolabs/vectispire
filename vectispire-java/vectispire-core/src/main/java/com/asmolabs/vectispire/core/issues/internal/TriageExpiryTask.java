package com.asmolabs.vectispire.core.issues.internal;

import com.asmolabs.vectispire.core.issues.IssueTriageService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The triage decisions that reached their review date, returned under review.
 *
 * <p><b>Nothing called {@code expireStale} for as long as it existed, and that is what the feature was
 * missing.</b> An acceptance could be recorded "for thirty days", the review date was stored, the
 * SARIF document said "to review on …" — and it never came back, because the method was reachable
 * only from its own tests. Its javadoc said it was called from the maintenance tick, which was the
 * only place the claim existed.
 *
 * <p>Hourly rather than on page load: a dismissal that lapses overnight has to stop dismissing in the
 * VEX document a customer downloads and in the verdict a pipeline asks for at three in the morning.
 * The worst case is that an acceptance outlives its date by an hour.
 */
@Component
@Order(MaintenanceTask.Sequence.TRIAGE_EXPIRY)
public class TriageExpiryTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(TriageExpiryTask.class);

    private final IssueTriageService triage;

    public TriageExpiryTask(IssueTriageService triage) {
        this.triage = triage;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        List<Long> expired = triage.expireStale();
        if (!expired.isEmpty()) {
            log.info("Maintenance: {} triage decision(s) returned under review.", expired.size());
        }
    }
}
