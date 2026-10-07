package com.asmolabs.vectispire.core.outbox;

/**
 * A destination that exists and that this installation may not reach for now — a SIEM transport the
 * platform governor has switched off (decision 0040).
 *
 * <p><b>Neither a failure nor a gone destination.</b> A failure counts an attempt, and eight of them
 * abandon the message; a gone destination abandons it at once. Both would lose a security event because
 * of a switch that a governor may turn back on in a minute, and with nothing at the collector to say an
 * event was ever missed. A held message stays pending, its attempts unchanged, with this reason as its
 * last error — what an operator reads in the outbox — and is offered again after {@link
 * com.asmolabs.vectispire.common.domain.notifications.OutboxRetry#HOLD_INTERVAL}, for as long as it takes.
 */
public class HeldDeliveryException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public HeldDeliveryException(String message) {
        super(message);
    }
}
