package com.asmolabs.vectispire.core.services.outbox;

import java.util.UUID;

/**
 * Delivers an outbox message that is not a scan notification.
 *
 * <p><b>Why a second interface rather than one more {@link NotificationChannel}.</b> A channel is a
 * destination for a scan's delta: {@code ScanDeltaNotifier} queues one row per configured channel
 * on every scan. A SIEM event registered as a channel would have been handed every scan delta, and
 * would have had to parse a {@code NotificationPayload} it has no use for. The relay's retry, claim
 * and abandonment are what both need; what each message <em>is</em> is not shared, so the payload
 * reaches the handler as the text that was stored, and the handler reads its own shape.
 *
 * <p>Like a channel, a handler <b>throws on failure</b> — the relay turns the exception into a
 * retry — and throws {@link GoneDestinationException} when the destination no
 * longer exists, which the relay abandons at once rather than retrying for four hours.
 */
public interface OutboxHandler {

    /** The outbox {@code message_type} this handler delivers. Stored on every row, so it must not move. */
    String type();

    /**
     * @param messageId the row's identifier, also stamped into the payload as {@code message_id}:
     *     delivery is at-least-once, and this is what a receiver deduplicates on
     * @param payload the JSON that was queued, exactly as stored
     */
    void deliver(UUID messageId, String payload);
}
