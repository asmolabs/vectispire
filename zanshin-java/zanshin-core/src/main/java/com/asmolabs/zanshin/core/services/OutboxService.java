package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload;
import com.asmolabs.zanshin.common.domain.notifications.OutboxRetry;
import com.asmolabs.zanshin.core.persistence.OutboxMessageEntity;
import com.asmolabs.zanshin.core.repositories.Outbox;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The relay that drains the notification queue.
 *
 * <p>Apart from {@link NotificationService} on purpose: that one owns <b>what to say</b>, this
 * one owns <b>when a message gets another chance</b>.
 *
 * <p><b>{@link #enqueue} opens no transaction of its own, and that is the whole point</b>: the
 * message has to become durable at the same instant as the state it describes, or the crash it
 * exists to survive simply moves down one line.
 */
@Service
public class OutboxService {

    private static final Logger log = LoggerFactory.getLogger(OutboxService.class);

    /** Every message this service writes describes what one scan changed. */
    public static final String TYPE_SCAN_DELTA = "scan_delta";

    private static final String STATUS_PENDING = "pending";
    private static final String STATUS_SENT = "sent";
    private static final String STATUS_FAILED = "failed";

    private final Outbox messages;
    private final NotificationService notifications;
    private final ObjectMapper json;
    private final Clock clock;

    /**
     * Opened explicitly, for the reason spelt out in {@code ScanDispatcher}: {@code
     * @Transactional} on a method this class calls itself is bypassed by the proxy and protects
     * nothing while reading as a guarantee.
     */
    private final TransactionTemplate transactions;

    public OutboxService(
            Outbox messages,
            NotificationService notifications,
            ObjectMapper json,
            Clock clock,
            TransactionTemplate transactions) {
        this.messages = messages;
        this.notifications = notifications;
        this.json = json;
        this.clock = clock;
        this.transactions = transactions;
    }

    /** @param sent delivered this pass; @param failed will be retried; @param abandoned out of attempts */
    public record RelayResult(int sent, int failed, int abandoned) {}

    /**
     * Adds a message to the transaction <b>the caller already opened</b>.
     *
     * <p>{@code MANDATORY}, not {@code REQUIRED}: a caller with no transaction would get one of
     * its own here, and the message would commit independently of the scan it describes —
     * announcing issues a rollback then removed.
     *
     * <p>A message identifier is stamped into the payload because delivery is at-least-once —
     * the POST can succeed and the transaction marking it sent can fail — and the receiver is
     * the only place that ambiguity can be resolved.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public OutboxMessageEntity enqueue(Object payload, String messageType) {
        UUID id = UUID.randomUUID();
        ObjectNode body = json.valueToTree(payload);
        body.put("message_id", id.toString());

        OutboxMessageEntity message = new OutboxMessageEntity();
        message.setId(id);
        message.setMessageType(messageType);
        message.setPayload(body.toString());
        message.setStatus(STATUS_PENDING);
        message.setAttempts(0);
        message.setNextAttemptAt(null);
        message.setLastError(null);
        message.setCreatedAt(clock.instant());
        message.setSentAt(null);
        return messages.save(message);
    }

    /**
     * Tries each due message once. Returns what happened.
     *
     * <p><b>Never throws</b>: this runs on the maintenance tick beside the other jobs, and an
     * unreachable webhook must not stop the rest.
     *
     * <p>Each message is settled in <b>its own transaction</b>, and not one for the pass: the
     * twelfth message failing must not undo the eleven deliveries already recorded, which would
     * send them all again on the next tick.
     */
    public RelayResult relay(int limit) {
        Instant at = clock.instant();
        List<OutboxMessageEntity> due = messages.findDue(STATUS_PENDING, at, Limit.of(limit));

        int sent = 0;
        int failed = 0;
        int abandoned = 0;

        for (OutboxMessageEntity message : due) {
            int attempts = message.getAttempts() + 1;
            try {
                notifications.deliver(payloadOf(message));
            } catch (JsonProcessingException | RuntimeException error) {
                if (Boolean.TRUE.equals(
                        transactions.execute(status -> settleFailure(message, attempts, at, error)))) {
                    abandoned++;
                } else {
                    failed++;
                }
                continue;
            }
            transactions.executeWithoutResult(status -> markSent(message.getId(), attempts, at));
            sent++;
        }

        if (sent > 0) {
            log.info("Outbox: {} message(s) delivered.", sent);
        }
        return new RelayResult(sent, failed, abandoned);
    }

    /** Deletes messages delivered long enough ago. The table is written on every scan. */
    @Transactional
    public int pruneSent() {
        return messages.deleteSentBefore(STATUS_SENT, clock.instant().minus(OutboxRetry.SENT_RETENTION));
    }

    /** The counts per status — abandonments included, which the screen has to show. */
    @Transactional(readOnly = true)
    public Map<String, Long> counts() {
        Map<String, Long> counts = new HashMap<>();
        for (Object[] row : messages.countByStatus()) {
            counts.put((String) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    /** @return whether the message was abandoned for good */
    private boolean settleFailure(OutboxMessageEntity message, int attempts, Instant at, Throwable error) {
        boolean abandonedNow = OutboxRetry.isAbandoned(attempts);
        Optional<Instant> next = OutboxRetry.nextAttemptAt(attempts, at);
        String reason = OutboxRetry.recordableError(error);

        messages.recordAttempt(
                message.getId(), attempts, reason, abandonedNow ? STATUS_FAILED : STATUS_PENDING, next.orElse(null));

        if (abandonedNow) {
            log.error("Notification {} abandoned after {} attempts: {}", message.getId(), attempts, reason);
        } else {
            log.warn(
                    "Notification {} failed (attempt {}/{}), retrying at {}.",
                    message.getId(),
                    attempts,
                    OutboxRetry.MAX_ATTEMPTS,
                    next.map(Instant::toString).orElse("never"));
        }
        return abandonedNow;
    }

    private void markSent(UUID id, int attempts, Instant at) {
        messages.markSent(id, attempts, STATUS_SENT, at);
    }

    /**
     * Reads a stored message back into the record that was queued.
     *
     * <p><b>The type is checked, not assumed.</b> The column holds text and the table is generic
     * by {@code message_type}; parsing whatever is there as a scan delta would, for any second
     * message type, produce a payload of zeroes rather than an error — the mapper is configured
     * not to fail on unknown properties, precisely so a rolling upgrade survives, and that
     * tolerance is what would make the mistake silent.
     */
    private NotificationPayload payloadOf(OutboxMessageEntity message) throws JsonProcessingException {
        if (!TYPE_SCAN_DELTA.equals(message.getMessageType())) {
            throw new IllegalStateException(
                    "Outbox message " + message.getId() + " has unknown type " + message.getMessageType());
        }
        return json.readValue(message.getPayload(), NotificationPayload.class);
    }
}
