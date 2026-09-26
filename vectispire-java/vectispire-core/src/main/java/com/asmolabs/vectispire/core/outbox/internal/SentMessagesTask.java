package com.asmolabs.vectispire.core.outbox.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The delivered messages purged, hourly.
 *
 * <p>Here rather than in the relay: the table is written on every scan, but the cleanup has no
 * reason to run every minute.
 */
@Component
@Order(MaintenanceTask.Sequence.SENT_MESSAGES)
public class SentMessagesTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(SentMessagesTask.class);

    private final OutboxService outbox;

    public SentMessagesTask(OutboxService outbox) {
        this.outbox = outbox;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        int delivered = outbox.pruneSent();
        if (delivered > 0) {
            log.info("Maintenance: {} delivered notification(s) purged.", delivered);
        }
    }
}
