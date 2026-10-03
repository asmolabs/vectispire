package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The report runs no executor holds or will claim, failed (decision 0035 §2): those whose lease lapsed, {@code
 * executor_lost}, and those nothing claimed for a whole lease while no executor was at work, {@code
 * executor_unavailable} — {@link ReportQueue}'s two sweeps.
 *
 * <p><b>Here, and not only in the worker's turn</b>, because the worker turns idle where there is no executor:
 * a control plane restarted with its built-in worker switched off kept every run it had queued {@code pending},
 * and every run it had in hand {@code running}, for ever — each holding its plugin's turn for its project, and
 * read on screen as about to happen. Every instance runs it, on the scheduler's minute; both sweeps are
 * conditional updates, so two instances fail a run once.
 */
@Component
@Order(MaintenanceTask.Sequence.REPORT_RUN_SWEEP)
public class ReportRunSweepTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(ReportRunSweepTask.class);

    private final ReportQueue queue;

    public ReportRunSweepTask(ReportQueue queue) {
        this.queue = queue;
    }

    @Override
    public Cadence cadence() {
        return Cadence.SCHEDULING;
    }

    @Override
    public void run() {
        List<Long> lost = queue.failLapsed();
        List<Long> unclaimed = queue.failUnclaimed();
        if (!lost.isEmpty() || !unclaimed.isEmpty()) {
            log.warn("Report runs failed: {} whose executor stopped answering, {} that no executor claimed.",
                    lost.size(), unclaimed.size());
        }
    }
}
