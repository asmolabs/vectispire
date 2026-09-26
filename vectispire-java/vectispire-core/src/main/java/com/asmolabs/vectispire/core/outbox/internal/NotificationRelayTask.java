package com.asmolabs.vectispire.core.outbox.internal;

import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The notification relay, every minute.
 *
 * <p>The batch is the backoff policy's {@link OutboxRetry#MAX_PER_PASS}, not a number chosen here:
 * two answers to "how many per pass" would drift. Several instances may relay at once — the relay
 * claims each message before sending it.
 */
@Component
@Order(MaintenanceTask.Sequence.NOTIFICATION_RELAY)
public class NotificationRelayTask implements MaintenanceTask {

    private final OutboxService outbox;

    public NotificationRelayTask(OutboxService outbox) {
        this.outbox = outbox;
    }

    @Override
    public Cadence cadence() {
        return Cadence.RELAY;
    }

    @Override
    public void run() {
        outbox.relay(OutboxRetry.MAX_PER_PASS);
    }
}
