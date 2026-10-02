package com.asmolabs.vectispire.core.siem;

import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventRaised;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventRaisedApart;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemSeverityFilter;
import com.asmolabs.vectispire.core.audit.AuditChainBroken;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
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
 *   <li>{@link #recordedInTransaction} — <b>the one hook</b>. Every audit entry passes here inside
 *       its own transaction, so the event commits with it ({@link #recorded} is the audit log's
 *       fallback when the two could not); the entries that signal an event, by their operation or
 *       because their writer named one, become an event. Actor, address, target and action come from the entry,
 *       so the event says what the audit log says. <b>The address is only as good as the entry's</b>:
 *       sign-in, MFA, the bearer ceiling and the gate resolve it through {@code TrustedProxies};
 *       entries written through {@code RequestActors} still record the servlet's peer address, which
 *       behind a load balancer is the balancer — a defect of the audit trail, and of this feed until
 *       it is fixed there.
 *   <li>{@link #enqueue} and {@link #publish} — for the few events with no audit entry behind them:
 *       a KEV reclassification, a gate refusal.
 *   <li>{@link #auditChainBroken} — the audit log's own alarm, an application event rather than a
 *       call, so that the audit log, which the SIEM listens to, does not call the SIEM back.
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

    private final SiemConfigRepository configs;
    private final OutboxService outbox;

    /**
     * {@code REQUIRES_NEW}, for {@link #publish}: it is called after the caller's own state has
     * committed, and from {@link #recorded}, which runs in the audit transaction's after-commit
     * callback — where, as Spring's own documentation warns, anything not in a new transaction would
     * still join the one that has just committed.
     */
    private final TransactionTemplate separately;

    public SiemEvents(SiemConfigRepository configs, OutboxService outbox, PlatformTransactionManager transactions) {
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
     * @param cefSeverity the event's own severity, stored because it is not always the type's — a
     *     remediation breach is as severe as its issue, and a relayed one must say so. {@code null} in a
     *     row queued before it was stored, which leaves at its type's severity, as it would have then
     */
    public record QueuedEvent(
            String eventType, long timestamp, String message, Map<String, String> extensions, Integer cefSeverity) {

        static QueuedEvent of(CefEvent event) {
            return new QueuedEvent(event.eventType().name(), event.timestamp().toEpochMilli(), event.message(),
                    event.extensions(), event.cefSeverity());
        }

        /** Empty when the type is one this version does not know: a row written by a newer one, during an upgrade. */
        Optional<CefEvent> toEvent(String messageId) {
            Optional<SecurityEventType> type = java.util.Arrays.stream(SecurityEventType.values())
                    .filter(candidate -> candidate.name().equals(eventType))
                    .findFirst();
            return type.map(known -> new CefEvent(known, Instant.ofEpochMilli(timestamp), message, withId(messageId),
                    cefSeverity == null ? known.cefSeverity() : cefSeverity));
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
     * <p>Call it outside any open write transaction: inside one, the event would report a state that
     * may still roll back, on a second connection held while the first keeps its locks. A caller in
     * a transaction enqueues in it instead (decision 0033).
     */
    public void publish(CefEvent event) {
        try {
            separately.executeWithoutResult(status -> queue(event));
        } catch (RuntimeException failed) {
            log.error("SIEM event {} could not be queued: {}", event.eventType(), failed.getMessage(), failed);
        }
    }

    /**
     * A module's security event, queued in the module's transaction (decision 0033, lot 5).
     *
     * <p>{@code MANDATORY} on the listener, as on {@link #enqueue}: an event raised outside a transaction
     * would commit independently of what it describes. Synchronous, so that a failure here fails the
     * publisher's transaction exactly as the call did.
     */
    @EventListener
    @Transactional(propagation = Propagation.MANDATORY)
    public void raised(SecurityEventRaised raised) {
        queue(raised.event());
    }

    /** A security event raised after what it describes committed — queued apart, and never failing its publisher. */
    @EventListener
    public void raisedApart(SecurityEventRaisedApart raised) {
        publish(raised.event());
    }

    /**
     * The hook: an audit entry that signals a security event becomes one, <b>in the entry's
     * transaction</b>.
     *
     * <p>The event and its entry commit together, so an event exists exactly when its entry does —
     * which was the claim when this ran after the commit, in a transaction of its own, and a stop
     * between the two made it false with nothing to send the event again (decision 0033). Entries
     * that signal nothing cost no query.
     */
    @Override
    public void recordedInTransaction(AuditLogService.Record entry, Instant at) {
        signalledBy(entry, at).ifPresent(this::queue);
    }

    /** The same event, after the entry committed apart from it — the audit log's fallback when the two could not commit together. */
    @Override
    public void recorded(AuditLogService.Record entry, Instant at) {
        signalledBy(entry, at).ifPresent(this::publish);
    }

    private static Optional<CefEvent> signalledBy(AuditLogService.Record entry, Instant at) {
        Optional<SecurityEventType> signalled = entry.signal() != null
                ? Optional.of(entry.signal())
                : SecurityEventType.signalledBy(entry.operation());
        return signalled.map(type -> CefEvent.builder(type)
                .timestamp(at)
                .message(bounded(entry.description()))
                .user(entry.userId())
                .sourceIp(entry.ipAddress())
                .action(entry.operation().wireName())
                .target(entry.resourceId())
                .userAgent(entry.userAgent())
                .build());
    }

    /**
     * A verification found the trail tampered with.
     *
     * <p>Heard synchronously, in the verifying request's thread and outside any transaction — see
     * {@code AuditLogQueryService#verify} for why not after a commit. {@link #publish} gives it a
     * transaction of its own and swallows a failure, so the verification answers whatever the
     * export does.
     */
    @EventListener
    public void auditChainBroken(AuditChainBroken broken) {
        publish(CefEvent.builder(SecurityEventType.AUDIT_CHAIN_BROKEN)
                .message(broken.describe())
                .action("AUDIT_VERIFIED")
                .target(broken.brokenAt())
                .build());
    }

    private void queue(CefEvent event) {
        if (event.eventType() == SecurityEventType.PING_TEST
                || event.eventType() == SecurityEventType.SIEM_EXPORT_STOPPED) {
            // The connection test is sent synchronously by the route; queued, it would reach the
            // collector a minute later and prove nothing about the moment the button was pressed.
            // The stop notice is sent synchronously by the save, to the collector being left;
            // queued, it would be read against the configuration that no longer names that one.
            return;
        }
        Optional<SiemConfigEntity> config = configs.findById(SiemConfigEntity.SINGLETON_ID);
        boolean exporting = config.map(found -> found.isEnabled()
                        && found.getEndpoint() != null
                        && !found.getEndpoint().isBlank())
                .orElse(false);
        if (!exporting || !SiemSeverityFilter.admits(event, config.get().getMinSeverity())) {
            return;
        }
        outbox.enqueue(QueuedEvent.of(event), TYPE);
    }

    private static String bounded(String message) {
        return message == null || message.length() <= MAX_MESSAGE_LENGTH ? message : message.substring(0, MAX_MESSAGE_LENGTH);
    }
}
