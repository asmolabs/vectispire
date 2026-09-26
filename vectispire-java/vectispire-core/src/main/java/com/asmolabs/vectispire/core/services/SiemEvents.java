package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemSeverityFilter;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.repositories.SiemConfigs;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Queues the security events a SOC receives, so that each is sent only if what caused it committed.
 *
 * <h2>Why the outbox, and not a call</h2>
 *
 * <p>The export was an {@code @Async} method in a codebase with no {@code @EnableAsync}: it ran
 * synchronously, inside the threat-intelligence sync's transaction, before the commit — an HTTP
 * POST holding the sync's row locks for up to ten seconds, and an event announced for a
 * reclassification that could still roll back. It is a row in {@code t_outbox_message} now, written
 * in the transaction it describes, sent by the relay after the commit with the relay's claim,
 * backoff and abandonment (see {@code OutboxRetry}), and never on the path of a scan ingest, a sync
 * or a sign-in.
 *
 * <p><b>At least once, not exactly once.</b> A collector can accept an event and the transaction
 * recording the delivery can fail; the event is then sent again. Each carries the outbox message
 * identifier as CEF {@code externalId}, which is what a SOC deduplicates on.
 *
 * <h2>Two ways in</h2>
 *
 * <ul>
 *   <li>{@link #recorded} — <b>the one hook</b>. Every audit entry passes here after its own
 *       transaction commits; the entries that signal an event, by their operation or because their
 *       writer named one, become an event. Actor, address, target and action come from the entry,
 *       so the event says what the audit log says. <b>The address is only as good as the entry's</b>:
 *       sign-in, MFA, the bearer ceiling and the gate resolve it through {@code TrustedProxies};
 *       entries written through {@code RequestActors} still record the servlet's peer address, which
 *       behind a load balancer is the balancer — a defect of the audit trail, and of this feed until
 *       it is fixed there.
 *   <li>{@link #enqueue} and {@link #publish} — for the few events with no audit entry behind them:
 *       a KEV reclassification, a gate refusal, a broken audit chain.
 * </ul>
 *
 * <p>Nothing is queued when the export is off, has no endpoint, or the event is below the configured
 * minimum severity: the table is written on every scan already, and a queue of messages nobody will
 * send is a queue an operator has to learn to ignore.
 */
@Service
public class SiemEvents implements AuditLogService.Listener {

    private static final Logger log = LoggerFactory.getLogger(SiemEvents.class);

    /** The outbox {@code message_type}. Stored on every row: it must not move. */
    public static final String TYPE = "siem_event";

    /** Enough for any audit description, bounded so one oversized value cannot bloat every row. */
    static final int MAX_MESSAGE_LENGTH = 1_024;

    private final SiemConfigs configs;
    private final OutboxService outbox;

    /**
     * {@code REQUIRES_NEW}, for {@link #publish}: it is called after the caller's own state has
     * committed, and from {@link #recorded}, which runs in the audit transaction's after-commit
     * callback — where, as Spring's own documentation warns, anything not in a new transaction would
     * still join the one that has just committed.
     */
    private final TransactionTemplate separately;

    public SiemEvents(SiemConfigs configs, OutboxService outbox, PlatformTransactionManager transactions) {
        this.configs = configs;
        this.outbox = outbox;
        this.separately = new TransactionTemplate(transactions);
        this.separately.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * What is stored in the outbox row: the event, not its rendering. The CEF line is rendered at
     * delivery, so the product version and the message identifier it carries are the ones in force
     * when it leaves, and the column holds data rather than a format.
     *
     * @param eventType the {@link SecurityEventType} constant's name
     * @param timestamp epoch milliseconds, which is what CEF's {@code rt} carries anyway
     */
    public record QueuedEvent(String eventType, long timestamp, String message, Map<String, String> extensions) {

        static QueuedEvent of(CefEvent event) {
            return new QueuedEvent(
                    event.eventType().name(), event.timestamp().toEpochMilli(), event.message(), event.extensions());
        }

        /** Empty when the type is one this version does not know: a row written by a newer one, during an upgrade. */
        Optional<CefEvent> toEvent(String messageId) {
            Optional<SecurityEventType> type = java.util.Arrays.stream(SecurityEventType.values())
                    .filter(candidate -> candidate.name().equals(eventType))
                    .findFirst();
            return type.map(known -> new CefEvent(known, Instant.ofEpochMilli(timestamp), message, withId(messageId)));
        }

        private Map<String, String> withId(String messageId) {
            Map<String, String> all = new java.util.LinkedHashMap<>(extensions == null ? Map.of() : extensions);
            all.put("externalId", messageId);
            return all;
        }
    }

    /**
     * Adds an event to the transaction <b>the caller already opened</b> — {@code MANDATORY}, like
     * {@link OutboxService#enqueue}, and for its reason: a caller with no transaction would commit
     * the event independently of what it describes.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void enqueue(CefEvent event) {
        queue(event);
    }

    /**
     * Queues an event in a transaction of its own, for a caller whose state has already committed or
     * that has none. <b>Never throws</b>: the export must not fail the action it reports on.
     *
     * <p>Call it outside any open write transaction: on SQLite, where the lock is the file, a second
     * transaction opened inside the first waits on it until it times out — the trap the audit log
     * documents.
     */
    public void publish(CefEvent event) {
        try {
            separately.executeWithoutResult(status -> queue(event));
        } catch (RuntimeException failed) {
            log.error("SIEM event {} could not be queued: {}", event.eventType(), failed.getMessage(), failed);
        }
    }

    /**
     * The hook: an audit entry that signals a security event becomes one.
     *
     * <p>Called after the entry's transaction commits, so an event exists exactly when its audit
     * entry does. Entries that signal nothing cost no query.
     */
    @Override
    public void recorded(AuditLogService.Record entry, Instant at) {
        Optional<SecurityEventType> signalled = entry.signal() != null
                ? Optional.of(entry.signal())
                : SecurityEventType.signalledBy(entry.operation());
        signalled.ifPresent(type -> publish(CefEvent.builder(type)
                .timestamp(at)
                .message(bounded(entry.description()))
                .user(entry.userId())
                .sourceIp(entry.ipAddress())
                .action(entry.operation().wireName())
                .target(entry.resourceId())
                .userAgent(entry.userAgent())
                .build()));
    }

    private void queue(CefEvent event) {
        if (event.eventType() == SecurityEventType.PING_TEST) {
            // The connection test is sent synchronously by the route; queued, it would reach the
            // collector a minute later and prove nothing about the moment the button was pressed.
            return;
        }
        Optional<SiemConfigEntity> config = configs.findById(SiemConfigEntity.SINGLETON_ID);
        boolean exporting = config.map(found -> found.isEnabled()
                        && found.getEndpoint() != null
                        && !found.getEndpoint().isBlank())
                .orElse(false);
        if (!exporting || !SiemSeverityFilter.admits(event.eventType(), config.get().getMinSeverity())) {
            return;
        }
        outbox.enqueue(QueuedEvent.of(event), TYPE);
    }

    private static String bounded(String message) {
        return message == null || message.length() <= MAX_MESSAGE_LENGTH ? message : message.substring(0, MAX_MESSAGE_LENGTH);
    }
}
