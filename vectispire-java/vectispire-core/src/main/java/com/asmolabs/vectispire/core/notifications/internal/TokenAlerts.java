package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.settings.Integrations;
import java.util.List;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * An integration token's change of state, queued everywhere it is said: its audit entry — and through the audit
 * log's hook its SIEM event — and one message per configured channel.
 *
 * <p><b>In the transaction that records the change as said</b> ({@code MANDATORY}, a synchronous listener): the
 * owner of the token — {@code tickets}, {@code forges} — moves its "last said" row and publishes in one transaction,
 * so the record and every effect commit together or not at all. Sent after the commit by the relay, with its
 * retries: an alert written after the commit, in a transaction of its own, would be lost to a stop in between, and
 * the next turn — finding the change already recorded — would never say it again.
 *
 * <p><b>The audit entry too.</b> Written here rather than by the owner after its commit, for the same reason, and
 * written by the relay in the entry's usual short transaction, chained like any other ({@link TokenAlertAudit}). Its
 * operation names its event ({@code VECTI-SEC-038} to {@code 040}), which the SIEM export's hook forwards.
 *
 * <p><b>The global channels alone</b>, whatever the issue threshold says: the threshold is about findings, and a
 * token is the installation's, not a team's. No rate limit beyond the change itself: a token's state changes a few
 * times a year, and each change is said once.
 */
@Service
public class TokenAlerts {

    private final OutboxService outbox;
    private final List<AlertChannel> channels;
    private final Integrations integrations;

    public TokenAlerts(OutboxService outbox, List<AlertChannel> channels, Integrations integrations) {
        this.outbox = outbox;
        this.channels = channels;
        this.integrations = integrations;
    }

    @EventListener
    @Transactional(propagation = Propagation.MANDATORY)
    public void changed(TokenAlert alert) {
        outbox.enqueue(alert, TokenAlertAudit.TYPE);
        // One row per destination, as for a scan's delta: one channel down must be retried on its own, without
        // sending the others twice.
        // A channel switched off (decision 0040, lot I6) is queued nothing, as one without a destination is.
        channels.stream()
                .filter(AlertChannel::isConfigured)
                .filter(channel -> ChannelGate.isOn(integrations, channel))
                .forEach
(channel -> outbox.enqueue(new TokenAlertDelivery.Queued(channel.alertKey(), alert),
                        TokenAlertDelivery.TYPE));
    }
}
