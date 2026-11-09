package com.asmolabs.vectispire.core.tickets.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.tickets.TicketSweepService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The ticket sweep, hourly and not every minute.
 *
 * <p>It is idempotent — the reference set on the issue is its deduplication key — so a tracker under
 * maintenance is simply retried next turn.
 */
@Component
@Order(MaintenanceTask.Sequence.TICKET_SWEEP)
public class TicketSweepTask implements MaintenanceTask {

    private final TicketSweepService tickets;

    public TicketSweepTask(TicketSweepService tickets) {
        this.tickets = tickets;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        tickets.sweep();
    }
}
