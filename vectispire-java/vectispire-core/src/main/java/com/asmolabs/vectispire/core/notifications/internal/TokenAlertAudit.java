package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.outbox.OutboxHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Writes the audit entry of a token's change of state, from the outbox — the message {@link TokenAlerts} queued in
 * the transaction that recorded the change as said.
 *
 * <p>The entry's operation is the event's ({@code INTEGRATION_TOKEN_EXPIRING}, {@code _STOPPED}, {@code
 * _RESTORED}), which the SIEM export's hook forwards in the entry's own transaction: one entry, one event. No actor:
 * nobody did this, and a "system" user would put a person who does not exist into the trail an assessor reads. The
 * resource is the tracker token's setting or the connection's identifier; the description is the alert's sentence —
 * never the token. <b>At least once</b>: written again if the relay's record of the delivery fails, the two carrying
 * the same delivery id.
 */
@Component
public class TokenAlertAudit implements OutboxHandler {

    /** The outbox {@code message_type}. Stored on every row: it must not move. */
    public static final String TYPE = "token_alert_audit";

    /**
     * Looked up at delivery, as {@code AgentResultAuditDelivery} does: the audit log is built with its listeners, the
     * SIEM export among them reaches the outbox, and the outbox is built with every handler — this one included.
     */
    private final ObjectProvider<AuditLogService> audit;
    private final ObjectMapper json;

    public TokenAlertAudit(ObjectProvider<AuditLogService> audit, ObjectMapper json) {
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
        TokenAlert alert;
        try {
            alert = json.readValue(payload, TokenAlert.class);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Token alert audit " + messageId + " has an unreadable payload", unreadable);
        }
        audit.getObject().append(new AuditLogService.Record(
                alert.operation(),
                alert.reference(),
                alert.sentence() + " Delivery " + messageId + ".",
                null,
                null,
                null));
    }
}
