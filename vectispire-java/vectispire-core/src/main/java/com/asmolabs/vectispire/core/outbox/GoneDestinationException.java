package com.asmolabs.vectispire.core.outbox;

/**
 * A destination that no longer exists.
 *
 * <p>Distinct from an unreachable one on purpose: the second deserves the twelve retries the
 * backoff policy grants, the first deserves none, because nothing about waiting will bring
 * back a team somebody deleted.
 *
 * <p><b>The relay's contract, not the notifications'.</b> It was nested in {@code
 * NotificationService}, which made the relay depend on the notifications it relays while they
 * enqueue into it — a cycle between two domains that a flat package hid. {@code OutboxService}
 * abandons on it, and every sender that can lose its destination — a channel, the SIEM delivery —
 * throws it.
 */
public class GoneDestinationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public GoneDestinationException(String message) {
        super(message);
    }
}
