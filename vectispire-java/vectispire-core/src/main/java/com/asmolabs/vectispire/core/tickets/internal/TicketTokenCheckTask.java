package com.asmolabs.vectispire.core.tickets.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.tickets.TicketService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The tracker token's check: its expiry read from the tracker once a day, and what there is to say about it —
 * fourteen days ahead, expired, refused — announced once when it changes.
 *
 * <p>On the hourly turn and not on a daily one of its own: the tick has no daily turn, and the day is counted
 * by the service from the tracker's last answer, as the EPSS feed counts its own. The hour still matters for
 * the announcement, which follows the clock rather than the tracker.
 */
@Component
@Order(MaintenanceTask.Sequence.TICKET_TOKEN_CHECK)
public class TicketTokenCheckTask implements MaintenanceTask {

    private final TicketService tickets;

    public TicketTokenCheckTask(TicketService tickets) {
        this.tickets = tickets;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        tickets.checkTokenIfDue();
    }
}
