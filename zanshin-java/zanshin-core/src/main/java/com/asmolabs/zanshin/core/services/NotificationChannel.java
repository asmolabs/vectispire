package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload;

/**
 * One destination a scan's delta can reach.
 *
 * <h2>Several, and independently</h2>
 *
 * <p><b>Not a choice between formats.</b> A team wants the card in its channel <em>and</em> the
 * mail on a distribution list, and modelling that as one setting with three values would force
 * an answer nobody's organisation actually has.
 *
 * <p>Which means each destination gets <b>its own outbox row</b>. Delivering three from one row
 * makes a partial failure unrepresentable: Teams accepted, the relay retries, and Teams receives
 * the message twice for a mail server that was down. Per-row is what lets the backoff be about
 * one destination.
 *
 * <p>Every implementation <b>throws on failure</b>, like the webhook always did — the relay is
 * what turns an exception back into "not fatal, retry later", and a swallowed failure is a
 * failure never retried.
 */
public interface NotificationChannel {

    /** The outbox {@code message_type} that routes to this channel. Stored, so it must not move. */
    String type();

    /** Whether this deployment has somewhere to send. An unconfigured channel is queued nothing. */
    boolean isConfigured();

    void deliver(NotificationPayload payload);
}
