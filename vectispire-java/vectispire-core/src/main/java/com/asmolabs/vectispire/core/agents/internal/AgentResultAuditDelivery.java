package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.outbox.OutboxHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Writes the audit entry of an agent's accepted result, from the outbox — the message
 * {@code AgentProtocolService} queued in the result's transaction (decision 0033, lot 4).
 *
 * <p><b>Why not in the result's transaction itself.</b> The entry was written after the result's
 * commit, and a stop in between lost it for good: a re-sent result is answered {@code NoLongerYours},
 * so nothing wrote it again. Writing it inside the result's transaction would have held the audit
 * chain's lock (V66) for as long as the scan took to write, and every other entry of every instance
 * would have waited for it. Queued there instead, it commits with the result and is written here in
 * the entry's usual short transaction, chained like any other.
 *
 * <p><b>Dated by its description, not by its timestamp.</b> The entry's timestamp is when it is
 * written — up to a relay's interval after the result — because the chain orders entries by it; the
 * moment the result was accepted is in the description. <b>At least once</b>: if the relay's record of
 * the delivery fails after the entry was written, it is written again, and the two carry the same
 * delivery id, which is what tells a duplicate from a second submission.
 */
@Component
public class AgentResultAuditDelivery implements OutboxHandler {

    /** The outbox {@code message_type}. Stored on every row: it must not move. */
    public static final String TYPE = "agent_result_audit";

    /** What is queued: the entry's fields, as the route knew them when it accepted the result. */
    public record Queued(long scanId, String description, String agentName, String ipAddress, String userAgent) {}

    /**
     * <b>Looked up at delivery, not injected</b>, as {@code ChecklistAnswerDelivery} looks up its service:
     * the audit log is built with its listeners, the SIEM export among them reaches the outbox, and the
     * outbox is built with every handler — this one included. The relay delivers long after start-up.
     */
    private final ObjectProvider<AuditLogService> audit;
    private final ObjectMapper json;

    public AgentResultAuditDelivery(ObjectProvider<AuditLogService> audit, ObjectMapper json) {
        this.audit = audit;
        this.json = json;
    }

    @Override
    public String type() {
        return TYPE;
    }

    /** Throws when the entry cannot be written, so the relay retries it rather than marking it sent. */
    @Override
    public void deliver(UUID messageId, String payload) {
        Queued queued;
        try {
            queued = json.readValue(payload, Queued.class);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Agent result audit " + messageId + " has an unreadable payload", unreadable);
        }
        audit.getObject().append(new AuditLogService.Record(
                AuditOperation.AGENT_RESULT_SUBMITTED,
                String.valueOf(queued.scanId()),
                queued.description() + " Delivery " + messageId + ".",
                queued.agentName(),
                queued.ipAddress(),
                queued.userAgent()));
    }
}
