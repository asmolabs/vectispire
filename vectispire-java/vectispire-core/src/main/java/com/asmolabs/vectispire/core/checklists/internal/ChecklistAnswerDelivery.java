package com.asmolabs.vectispire.core.checklists.internal;

import com.asmolabs.vectispire.core.checklists.ProjectChecklistService;
import com.asmolabs.vectispire.core.outbox.OutboxHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Answers, from the outbox, the measured lines of the draft checklist of the project a repository is
 * filed in — the message {@link AnswersFromEvidence} queued in the scan's or the import's transaction
 * (decision 0033).
 *
 * <p><b>At least once, and idempotent for it.</b> The relay may deliver a message twice — the answer
 * written, the transaction recording the delivery lost — and answering twice from the same evidence
 * changes nothing: Vectispire's answer is rewritten only when what it states changes. A failure throws,
 * and the relay retries it with its backoff, then abandons it with the reason after its last attempt,
 * visible in the queue; the next scan or import answers again in any case.
 *
 * <p>Runs outside any transaction, like every handler: {@link ProjectChecklistService#answerFromEvidence}
 * opens its own.
 */
@Component
public class ChecklistAnswerDelivery implements OutboxHandler {

    /** The outbox {@code message_type}. Stored on every row: it must not move. */
    public static final String TYPE = "checklist_answer";

    /**
     * <b>Looked up at delivery, not injected.</b> The outbox is built with every handler, and the
     * checklists' service reaches the outbox back through the SIEM export it audits into: injected
     * here, the three made a cycle the context refused to start on. The relay delivers long after
     * start-up, by which time the service exists.
     */
    private final ObjectProvider<ProjectChecklistService> checklists;
    private final ObjectMapper json;

    public ChecklistAnswerDelivery(ObjectProvider<ProjectChecklistService> checklists, ObjectMapper json) {
        this.checklists = checklists;
        this.json = json;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public void deliver(UUID messageId, String payload) {
        JsonNode repositoryId;
        try {
            repositoryId = json.readTree(payload).path("repository_id");
        } catch (com.fasterxml.jackson.core.JsonProcessingException unreadable) {
            throw new IllegalStateException("Checklist answer " + messageId + " has an unreadable payload", unreadable);
        }
        if (!repositoryId.canConvertToLong()) {
            throw new IllegalStateException("Checklist answer " + messageId + " names no repository");
        }
        checklists.getObject().answerFromEvidence(repositoryId.asLong());
    }
}
