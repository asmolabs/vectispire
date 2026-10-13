package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.core.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.outbox.OutboxHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Delivers a queued {@link TokenAlert} to the channel its row names.
 *
 * <p><b>One message type, the channel in the payload</b>, rather than a type per channel as the scan delta has:
 * the relay hands a handler its row's payload and nothing else, and five handlers that differ by a word would be
 * five places to drift. The row is still one per destination, so a channel that is down is retried on its own.
 *
 * <p><b>The destination is read at the send</b>, by the channel, as for a scan's delta: an operator fixing a URL
 * flushes what waits. A channel no longer configured is {@link GoneDestinationException} — abandoned at once with
 * its reason, not retried for hours.
 */
@Component
public class TokenAlertDelivery implements OutboxHandler {

    /** The outbox {@code message_type}. Stored on every row: it must not move. */
    public static final String TYPE = "token_alert";

    /**
     * What is queued: the channel's {@link AlertChannel#alertKey} and the alert.
     *
     * @param channel {@code webhook}, {@code slack}, {@code teams}, {@code discord} or {@code mail}
     */
    public record Queued(String channel, TokenAlert alert) {}

    private final List<AlertChannel> channels;
    private final ObjectMapper json;

    public TokenAlertDelivery(List<AlertChannel> channels, ObjectMapper json) {
        this.channels = channels;
        this.json = json;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public void deliver(UUID messageId, String payload) {
        Queued queued;
        try {
            queued = json.readValue(payload, Queued.class);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Token alert " + messageId + " has an unreadable payload", unreadable);
        }
        AlertChannel channel = channels.stream()
                .filter(candidate -> candidate.alertKey().equals(queued.channel()))
                .findFirst()
                // A row written by a newer version, during an upgrade: an error, retried and then abandoned with its
                // reason — never a silent skip.
                .orElseThrow(() -> new IllegalStateException(
                        "Token alert " + messageId + " names an unknown channel: " + queued.channel()));
        if (!channel.isConfigured()) {
            throw new GoneDestinationException("the " + queued.channel() + " channel is no longer configured");
        }
        channel.deliverAlert(queued.alert(), messageId.toString());
    }
}
