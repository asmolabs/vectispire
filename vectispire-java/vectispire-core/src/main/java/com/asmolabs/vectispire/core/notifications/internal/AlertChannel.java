package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;

/**
 * A destination a {@link TokenAlert} can reach: the global webhook, Slack, Teams, Discord, mail.
 *
 * <p><b>The channels a scan's delta reaches, given a second message.</b> Each one already knows where it sends and
 * under which rule — its URL read at the send, the private-address switch, the signing secret, the relay and the
 * recipients — so the alert is delivered by the same class rather than by a second place that would drift from it.
 * A team's own webhook is not one of them: a token is the installation's, not a team's.
 *
 * <p>Like a {@code NotificationChannel}, it <b>throws on failure</b>, and the relay turns that into a retry.
 */
public interface AlertChannel {

    /** The channel's name in a queued alert. Stored in the outbox payload, so it must not move. */
    String alertKey();

    /** Whether this deployment has somewhere to send. An unconfigured channel is queued nothing. */
    boolean isConfigured();

    /**
     * @param messageId the outbox row's identifier, in the message: delivery is at-least-once, and this is what a
     *     receiver deduplicates on
     */
    void deliverAlert(TokenAlert alert, String messageId);
}
