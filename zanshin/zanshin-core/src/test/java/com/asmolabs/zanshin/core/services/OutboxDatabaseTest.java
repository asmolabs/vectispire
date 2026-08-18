package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.zanshin.common.domain.notifications.OutboxRetry;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import com.asmolabs.zanshin.core.persistence.OutboxMessageEntity;
import com.asmolabs.zanshin.core.repositories.Outbox;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Limit;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The outbox against a database.
 *
 * <p>Two things only a real one can settle: that {@code MANDATORY} actually refuses — the
 * guarantee that a queued notification commits with the state it describes — and that the due
 * query treats a never-tried message as due, which is a {@code null} check in SQL and the kind
 * of condition that reads correct and is not.
 */
@DisplayName("the notification queue, against a database")
class OutboxDatabaseTest extends ZanshinContextTest {

    @Autowired
    private OutboxService outbox;

    @Autowired
    private Outbox messages;

    @Autowired
    private TransactionTemplate transactions;

    @Test
    @DisplayName("enqueueing outside a transaction is refused, not silently given one")
    void mandatoryMeansMandatory() {
        // The guarantee, executed. A message that committed on its own would announce issues a
        // rollback then removed — the exact window the outbox exists to close.
        assertThatThrownBy(() -> outbox.enqueue(Map.of("scan_id", 1), OutboxService.TYPE_SCAN_DELTA))
                .isInstanceOf(IllegalTransactionStateException.class);

        assertThat(messages.findAll()).isEmpty();
    }

    @Test
    @DisplayName("a message rolled back with its caller never existed")
    void aRolledBackMessageIsNotQueued() {
        assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
                    outbox.enqueue(Map.of("scan_id", 1), OutboxService.TYPE_SCAN_DELTA);
                    throw new IllegalStateException("the scan failed after queueing");
                }))
                .isInstanceOf(IllegalStateException.class);

        assertThat(messages.findAll()).isEmpty();
    }

    @Test
    @DisplayName("the payload carries the identifier the row was given")
    void theStampedIdentifierMatchesTheRow() {
        OutboxMessageEntity stored = transactions.execute(
                status -> outbox.enqueue(Map.of("scan_id", 7), OutboxService.TYPE_SCAN_DELTA));

        // Assigned before the insert because it goes inside the payload — the reason the entity
        // is `Persistable`. If the two ever disagreed, a receiver would deduplicate on a value
        // nothing else refers to.
        assertThat(stored.getPayload()).contains(stored.getId().toString());
        assertThat(messages.findById(stored.getId())).isPresent();
    }

    @Test
    @DisplayName("a message never tried is due now")
    void aNeverTriedMessageIsDue() {
        transactions.executeWithoutResult(
                status -> outbox.enqueue(Map.of("scan_id", 7), OutboxService.TYPE_SCAN_DELTA));

        // `next_attempt_at is null` means "first attempt", not "not yet". Read the other way the
        // whole queue would sit permanently about to go out.
        assertThat(messages.findDue("pending", Instant.now(), Limit.of(20))).hasSize(1);
    }

    @Test
    @DisplayName("a message waiting for its retry is not due yet")
    void aScheduledRetryIsNotDue() {
        UUID id = transactions
                .execute(status -> outbox.enqueue(Map.of("scan_id", 7), OutboxService.TYPE_SCAN_DELTA))
                .getId();
        Instant now = Instant.now();
        messages.recordAttempt(id, 1, "connection refused", "pending", now.plusSeconds(600));

        assertThat(messages.findDue("pending", now, Limit.of(20))).isEmpty();
        assertThat(messages.findDue("pending", now.plusSeconds(601), Limit.of(20))).hasSize(1);
    }

    @Test
    @DisplayName("only delivered messages past their retention are pruned")
    void pruningSparesWhatIsStillPending() {
        UUID pending = transactions
                .execute(status -> outbox.enqueue(Map.of("scan_id", 1), OutboxService.TYPE_SCAN_DELTA))
                .getId();
        UUID sent = transactions
                .execute(status -> outbox.enqueue(Map.of("scan_id", 2), OutboxService.TYPE_SCAN_DELTA))
                .getId();
        messages.markSent(sent, 1, "sent", Instant.now().minus(OutboxRetry.SENT_RETENTION).minusSeconds(60));

        assertThat(outbox.pruneSent()).isEqualTo(1);
        assertThat(messages.findById(pending)).isPresent();
        assertThat(messages.findById(sent)).isEmpty();
    }
}
