package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.core.outbox.OutboxHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Hands a completed scan's request for an OWASP report, from the outbox, to this instance's report writer —
 * the message {@link OwaspReportOnScan} queued in the scan's transaction.
 *
 * <p><b>Handed over, not written here.</b> The relay delivers on the maintenance tick, beside every
 * notification and SIEM event, and claims a message for five minutes ({@code OutboxRetry.CLAIM_WINDOW}): a
 * model answering in six would have held the tick for all of it and had the message taken again by another
 * instance meanwhile. The delivery returns as soon as {@link OwaspReportsAfterScans} holds the request, and
 * the message is then sent. What that costs is written on that class: a request it holds and has not started
 * is lost if the process stops, and the next scan asks again.
 *
 * <p>A payload naming no repository or no scan throws, and the relay retries it and then abandons it with
 * the reason — never a silent skip.
 */
@Component
public class OwaspReportDelivery implements OutboxHandler {

    /** The outbox {@code message_type}. Stored on every row: it must not move. */
    public static final String TYPE = "owasp_report_after_scan";

    /**
     * <b>Looked up at delivery, not injected</b>, for the reason {@code ChecklistAnswerDelivery} gives: the
     * outbox is built with every handler, and the writer reaches the outbox back through the audit trail it
     * records into. The relay delivers long after start-up, by which time the writer exists.
     */
    private final ObjectProvider<OwaspReportsAfterScans> writer;
    private final ObjectMapper json;

    public OwaspReportDelivery(ObjectProvider<OwaspReportsAfterScans> writer, ObjectMapper json) {
        this.writer = writer;
        this.json = json;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public void deliver(UUID messageId, String payload) {
        JsonNode body;
        try {
            body = json.readTree(payload);
        } catch (com.fasterxml.jackson.core.JsonProcessingException unreadable) {
            throw new IllegalStateException("OWASP report request " + messageId + " has an unreadable payload", unreadable);
        }
        JsonNode repositoryId = body.path("repository_id");
        JsonNode scanId = body.path("scan_id");
        if (!repositoryId.canConvertToLong() || !scanId.canConvertToLong()) {
            throw new IllegalStateException("OWASP report request " + messageId + " names no repository or no scan");
        }
        writer.getObject().offer(repositoryId.asLong(), scanId.asLong());
    }
}
