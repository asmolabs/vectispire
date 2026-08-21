package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload.Detail;
import com.asmolabs.zanshin.common.domain.notifications.OutboxRetry;
import com.asmolabs.zanshin.core.persistence.OutboxMessageEntity;
import com.asmolabs.zanshin.core.repositories.Outbox;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

@DisplayName("draining the notification queue")
class OutboxServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T14:00:00Z");
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-00000000000f");

    private Outbox messages;
    private NotificationService notifications;
    private OutboxService service;

    @BeforeEach
    void wire() {
        messages = mock(Outbox.class);
        notifications = mock(NotificationService.class);

        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        service = new OutboxService(
                messages, notifications, new ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC),
                new TransactionTemplate(manager));

        when(messages.save(any())).thenAnswer(call -> call.getArgument(0));
        when(messages.findDue(anyString(), any(), any())).thenReturn(List.of());
    }

    @Test
    @DisplayName("the payload carries a message identifier, because delivery is at-least-once")
    void enqueueStampsAnIdentifier() {
        OutboxMessageEntity message = service.enqueue(Map.of("scan_id", 7), OutboxService.TYPE_SCAN_DELTA);

        // The POST can succeed and the transaction marking it sent can fail. The receiver is the
        // only place that ambiguity can be resolved, so it has to be told which message this is.
        assertThat(message.getPayload()).contains("\"message_id\":\"" + message.getId() + "\"");
        assertThat(message.getStatus()).isEqualTo("pending");
        assertThat(message.getNextAttemptAt()).isNull();
    }

    @Test
    void marksADeliveredMessageSent() {
        due(pending(0));

        assertThat(service.relay(20)).isEqualTo(new OutboxService.RelayResult(1, 0, 0));
        verify(messages).markSent(ID, 1, "sent", NOW);
    }

    @Test
    @DisplayName("a failure schedules the next attempt rather than losing the message")
    void aFailureIsRetried() {
        due(pending(0));
        doThrow(new OutboundJson.OutboundFailureException("connection refused")).when(notifications).deliver(any(), any());

        assertThat(service.relay(20)).isEqualTo(new OutboxService.RelayResult(0, 1, 0));
        verify(messages).recordAttempt(eq(ID), eq(1), anyString(), eq("pending"), any(Instant.class));
    }

    @Test
    @DisplayName("the last attempt abandons the message and says so")
    void theLastAttemptGivesUp() {
        due(pending(OutboxRetry.MAX_ATTEMPTS - 1));
        doThrow(new OutboundJson.OutboundFailureException("connection refused")).when(notifications).deliver(any(), any());

        assertThat(service.relay(20)).isEqualTo(new OutboxService.RelayResult(0, 0, 1));
        // Failed, with no next attempt: a message circulating for ever would hide the outage
        // behind a queue that never empties.
        verify(messages).recordAttempt(eq(ID), eq(OutboxRetry.MAX_ATTEMPTS), anyString(), eq("failed"), isNull());
    }

    @Test
    @DisplayName("one message failing does not undo the ones already delivered")
    void eachMessageIsSettledSeparately() {
        OutboxMessageEntity first = pending(0);
        OutboxMessageEntity second = pending(0);
        second.setId(UUID.fromString("00000000-0000-0000-0000-0000000000ff"));
        due(first, second);
        doThrow(new OutboundJson.OutboundFailureException("boom"))
                .doNothing()
                .when(notifications)
                .deliver(any(), any());

        assertThat(service.relay(20)).isEqualTo(new OutboxService.RelayResult(1, 1, 0));
    }

    @Test
    @DisplayName("an unreadable payload is a failure like any other, not a crash")
    void malformedJsonDoesNotStopThePass() {
        OutboxMessageEntity broken = pending(0);
        broken.setPayload("{not json");
        due(broken);

        assertThat(service.relay(20).failed()).isEqualTo(1);
    }

    @Test
    void countsByStatusForTheScreen() {
        when(messages.countByStatus()).thenReturn(List.of(new Object[] {"sent", 4L}, new Object[] {"failed", 1L}));

        assertThat(service.counts()).containsEntry("sent", 4L).containsEntry("failed", 1L);
    }

    @Test
    void prunesDeliveredMessagesPastTheirRetention() {
        when(messages.deleteSentBefore(anyString(), any())).thenReturn(3);

        assertThat(service.pruneSent()).isEqualTo(3);
        verify(messages).deleteSentBefore("sent", NOW.minus(OutboxRetry.SENT_RETENTION));
    }

    @Test
    @DisplayName("what comes back out of the queue is what went in, message identifier included")
    void thePayloadSurvivesTheRoundTrip() {
        NotificationPayload queued = NotificationPayload.of(new NotificationPayload.Delta(
                "service", 7, List.of(issue()), List.of(), 3, Severity.HIGH));
        OutboxMessageEntity stored = service.enqueue(queued, OutboxService.TYPE_SCAN_DELTA);
        due(stored);

        ArgumentCaptor<NotificationPayload> delivered = ArgumentCaptor.forClass(NotificationPayload.class);
        service.relay(20);
        verify(notifications).deliver(delivered.capture(), org.mockito.ArgumentMatchers.isNull());

        // The relay parses the stored text back into the record before posting it, so every field
        // the record does not declare is dropped — and the mapper is configured not to complain
        // about unknown properties, so it would be dropped without a word. `message_id` is the
        // one that matters: it is stamped by `enqueue` and is the receiver's only way to
        // recognise the repeat that at-least-once delivery will eventually send it.
        assertThat(delivered.getValue().messageId()).isEqualTo(stored.getId().toString());
        assertThat(delivered.getValue().scanId()).isEqualTo(7);
        assertThat(delivered.getValue().resolvedCount()).isEqualTo(3);
        assertThat(delivered.getValue().issues()).singleElement().returns("CVE-2026-1", Detail::identifier);
    }

    @Test
    @DisplayName("a message of an unknown type is refused, not delivered as an empty scan delta")
    void anUnknownTypeIsNotGuessedAt() {
        OutboxMessageEntity other = pending(0);
        other.setMessageType("digest");
        due(other);

        // Unknown properties are ignored by design, so parsing a digest as a scan delta would
        // succeed and produce zeroes — a webhook announcing that nothing happened. Failing the
        // message keeps it in the queue where somebody can see it.
        assertThat(service.relay(20).failed()).isEqualTo(1);
        verify(notifications, never()).deliver(any(), any());
    }

    private static NotificationPayload.NotifiableIssue issue() {
        return new NotificationPayload.NotifiableIssue(
                1L, "CVE-2026-1", FindingType.VULNERABILITY, Severity.HIGH, false, 0.4, "openssl", null, "3.5.2", null);
    }

    private void due(OutboxMessageEntity... pending) {
        when(messages.findDue(anyString(), any(), any())).thenReturn(List.of(pending));
    }

    private static OutboxMessageEntity pending(int attempts) {
        OutboxMessageEntity message = new OutboxMessageEntity();
        message.setId(ID);
        message.setMessageType(OutboxService.TYPE_SCAN_DELTA);
        message.setPayload("{\"scan_id\":7,\"new_count\":2,\"reopened_count\":0}");
        message.setStatus("pending");
        message.setAttempts(attempts);
        message.setCreatedAt(NOW.minusSeconds(600));
        return message;
    }
}
