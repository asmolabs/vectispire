package com.asmolabs.vectispire.core.services.tickets;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.WebhookDeliveryEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.WebhookDeliveries;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.issues.IssueTriageService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * What an issue tracker's webhook is allowed to change, and how its payload is read.
 *
 * <p>The outcomes are a closed set because each one is a different answer to the tracker — refused,
 * unreadable, nothing to do, done — and the status each maps to belongs next to the route.
 */
@Service
public class TicketingWebhookService {

    private static final Logger log = LoggerFactory.getLogger(TicketingWebhookService.class);

    private final Issues issues;
    private final IssueTriageService triageService;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final TicketService tickets;
    private final WebhookDeliveries deliveries;
    private final WebhookRefusals refusals;
    private final java.time.Clock clock;

    /** How long a delivery's body is remembered for the replay check. */
    private static final java.time.Duration REPLAY_WINDOW = java.time.Duration.ofDays(30);

    public TicketingWebhookService(
            Issues issues,
            IssueTriageService triageService,
            AuditLogService audit,
            ObjectMapper json,
            TicketService tickets,
            WebhookDeliveries deliveries,
            WebhookRefusals refusals,
            java.time.Clock clock) {
        this.issues = issues;
        this.triageService = triageService;
        this.audit = audit;
        this.json = json;
        this.tickets = tickets;
        this.deliveries = deliveries;
        this.refusals = refusals;
        this.clock = clock;
    }

    public sealed interface Outcome {
        /** The secret is configured and the call does not carry it, or the secret cannot be read. */
        record Rejected() implements Outcome {}

        /** No secret is configured, so nothing is accepted. */
        record NotConfigured() implements Outcome {}

        record Malformed() implements Outcome {}

        record NoReference() implements Outcome {}

        /** This exact body was already acted on: a replay, or the tracker's own redelivery. */
        record AlreadyProcessed() implements Outcome {}

        record NoMatchingIssue(String ticketRef) implements Outcome {}

        record Synced(Long issueId, String ticketRef, String actionTaken) implements Outcome {}
    }

    /**
     * Audits a refusal when {@link WebhookRefusals} says it earns an entry.
     *
     * <p>Every refusal used to write one, on the only anonymous route that writes: the audit log —
     * chained and never purged — could be filled by anybody who could reach the port.
     */
    private void recordRefusal(RequestActor origin, String description) {
        refusals.refused(origin.ipAddress()).ifPresent(note -> audit.record(AuditLogService.Record.of(
                AuditOperation.LOGIN_BLOCKED, "ticket_webhook", description + note, "anonymous")));
    }

    public Outcome handle(
            TicketProvider provider, String rawPayload, WebhookAuthenticity.Presented presented, RequestActor origin) {

        // **The system's only anonymous door: shut until a secret is set.** It cannot require a
        // session — the caller is the tracker — so the secret is the whole of its authentication.
        // With none configured it used to stay open, and once inside a stranger queued a "not
        // affected" for any ticket reference they guessed. Nothing is accepted without one now,
        // and a secret no key can read refuses like a wrong signature rather than reopening.
        TicketService.WebhookSecret secret = tickets.webhookSecret();
        if (secret instanceof TicketService.WebhookSecret.Absent) {
            recordRefusal(origin, "Refused " + provider + " webhook from " + origin.ipAddress()
                    + ": no webhook secret is configured");
            return new Outcome.NotConfigured();
        }
        WebhookAuthenticity.Verdict verdict = secret instanceof TicketService.WebhookSecret.Present(String value)
                ? WebhookAuthenticity.verify(provider, value, presented, rawPayload)
                : WebhookAuthenticity.Verdict.REJECTED;
        if (verdict != WebhookAuthenticity.Verdict.ACCEPTED) {
            // Audited, because a stream of these is somebody probing and the audit log is where
            // that becomes visible — sparingly, see `recordRefusal`. No detail in the response: a
            // caller learning *which* header was wrong learns which tracker we expect.
            recordRefusal(origin,
                    (secret instanceof TicketService.WebhookSecret.Unreadable
                                    ? "Refused " + provider + " webhook: the stored secret cannot be decrypted, from "
                                    : "Rejected unsigned or wrongly signed " + provider + " webhook from ")
                            + origin.ipAddress());
            return new Outcome.Rejected();
        }

        // **Once per body.** A signed delivery captured on the wire stayed valid for ever: sent again,
        // it queued the same decision again. Remembered by the hash of the body, which the
        // signature covers — not by the delivery id, which travels in a header it does not.
        Instant now = clock.instant();
        deliveries.deleteBefore(now.minus(REPLAY_WINDOW));
        String bodyHash = Sessions.hashOf(provider.wireName() + ":" + rawPayload);
        try {
            deliveries.saveAndFlush(new WebhookDeliveryEntity(bodyHash, provider.wireName(), now));
        } catch (org.springframework.dao.DataAccessException refused) {
            // The primary key refusing a duplicate is not translated the same way on every engine
            // — SQLite's dialect reports it as a generic JPA failure — so the row is asked for
            // rather than the exception's class trusted. A database that is down is not a replay.
            if (!deliveries.existsById(bodyHash)) {
                throw refused;
            }
            log.info("{} webhook body already processed; ignored.", provider);
            return new Outcome.AlreadyProcessed();
        }

        JsonNode payload;
        try {
            payload = json.readTree(rawPayload);
        } catch (Exception e) {
            return new Outcome.Malformed();
        }

        ExtractedTicketEvent event = extractEvent(provider, payload);

        if (event == null || event.ticketRef() == null || event.ticketRef().isBlank()) {
            return new Outcome.NoReference();
        }

        Optional<IssueEntity> matchingIssue = issues.findByTicketRefOrIid(event.ticketRef());
        if (matchingIssue.isEmpty()) {
            log.info("Received webhook for ticket {} from {} but no corresponding Vectispire issue found.", event.ticketRef(), provider);
            return new Outcome.NoMatchingIssue(event.ticketRef());
        }

        IssueEntity issue = matchingIssue.get();
        String actionTaken;

        if (event.isRefusedOrFalsePositive()) {
            TriageStatus status = TriageStatus.NOT_AFFECTED;
            VexJustification justification = event.isFalsePositive()
                    ? VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
                    : VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;

            // **The author is the integration, and the claimed name goes down into the comment.**
            // It used to come from the payload: on an anonymous route, that let the caller choose
            // the name the audit log — tamper-evident, never purged — was going to seal beside its
            // decision. The hash chain protects the entry against a later modification; it does not
            // protect against a lie dictated to it. The name stays useful and stays written, but as
            // reported data and not as an identity.
            String author = provider.name() + "_webhook";
            String claimed = event.author() != null && !event.author().isBlank()
                    ? " (reported by the tracker as: " + event.author() + ")"
                    : "";
            // Clipped, not refused: the tracker wrote it, nobody here can shorten it, and a refusal
            // would drop the decision it carries over the length of its prose.
            String comment = BoundedText.clip((event.comment() != null && !event.comment().isBlank()
                    ? event.comment()
                    : "Status updated from " + provider.name() + " ticket " + event.ticketRef())
                    + claimed, Triage.MAX_COMMENT_LENGTH);

            // **`false`, and that is the whole fix.** This boolean was `true`: a tracker's
            // decision settled on the spot, bypassing four-eyes. On a route that requires no
            // authentication as long as no secret is configured — the default — that meant an
            // anonymous POST could set `not_affected` with the justification
            // `vulnerable_code_not_in_execute_path`, which travels as it stands into the signed
            // CycloneDX, OpenVEX and CSAF documents handed to customers.
            //
            // It is the claim this repository has already withdrawn once: the reachability analyser
            // was made one-way so that no machine clears a component without a human, and
            // `CycloneDxGeneratorService.mapAnalysis` writes the invariant out in full — "triage
            // clears a component; reachability does not". This door was the hole in it: neither a
            // human, nor authenticated.
            //
            // **Nothing breaks.** `queueIfNotApprover` converts the decision into
            // `PENDING_APPROVAL` without consulting the four-eyes setting, and `pending_approval`
            // renders as "under review" in the documents, never as "not affected".
            // Synchronisation therefore goes on recording what the tracker says; it only stops
            // publishing it in a human's place.
            IssueEntity triaged = triageService.triage(
                    issue.getId(),
                    new Triage.Request(
                            status,
                            author,
                            justification,
                            comment,
                            null),
                    false);

            actionTaken = "Queued as " + triaged.getTriageStatus() + " (" + justification.wireName()
                    + ") from " + author;

            audit.record(new AuditLogService.Record(
                    AuditOperation.TICKET_SYNCED,
                    String.valueOf(issue.getId()),
                    "Issue triage automatically synchronized from " + provider.name() + " ticket " + event.ticketRef() + ": " + actionTaken,
                    author,
                    origin.ipAddress(),
                    origin.userAgent()));
        } else {
            actionTaken = "Ticket updated on " + provider.name() + " (status: " + event.status() + ")";
            audit.record(new AuditLogService.Record(
                    AuditOperation.TICKET_SYNCED,
                    String.valueOf(issue.getId()),
                    "Ticket update received from " + provider.name() + " for " + event.ticketRef() + " (status: " + event.status() + ")",
                    event.author(),
                    origin.ipAddress(),
                    origin.userAgent()));
        }

        return new Outcome.Synced(issue.getId(), event.ticketRef(), actionTaken);
    }

    private record ExtractedTicketEvent(
            String ticketRef,
            String status,
            String resolution,
            String comment,
            String author,
            boolean isRefusedOrFalsePositive,
            boolean isFalsePositive) {}

    private ExtractedTicketEvent extractEvent(TicketProvider provider, JsonNode root) {
        if (root == null) return null;

        switch (provider) {
            case GITLAB -> {
                JsonNode attrs = root.path("object_attributes");
                String iid = attrs.path("iid").asText("");
                String state = attrs.path("state").asText("");
                String title = attrs.path("title").asText("");
                String author = root.path("user").path("username").asText("");
                String comment = attrs.path("description").asText("");

                boolean isFp = title.toLowerCase(Locale.ROOT).contains("false positive") || comment.toLowerCase(Locale.ROOT).contains("false positive");
                boolean isWontFix = state.equalsIgnoreCase("closed") && (title.toLowerCase(Locale.ROOT).contains("wontfix") || title.toLowerCase(Locale.ROOT).contains("won't fix") || isFp);

                return new ExtractedTicketEvent(iid, state, null, comment, author, isWontFix || isFp, isFp);
            }
            case GITHUB -> {
                JsonNode issueNode = root.path("issue");
                String number = issueNode.path("number").asText("");
                String state = issueNode.path("state").asText("");
                String stateReason = issueNode.path("state_reason").asText("");
                String author = root.path("sender").path("login").asText("");
                String body = issueNode.path("body").asText("");

                boolean isFp = stateReason.equalsIgnoreCase("not_planned") || body.toLowerCase(Locale.ROOT).contains("false positive");
                boolean isWontFix = isFp || stateReason.equalsIgnoreCase("not_planned");

                return new ExtractedTicketEvent(number, state, stateReason, body, author, isWontFix, isFp);
            }
            case JIRA -> {
                JsonNode issueNode = root.path("issue");
                String key = issueNode.path("key").asText("");
                JsonNode fields = issueNode.path("fields");
                String status = fields.path("status").path("name").asText("");
                String resolution = fields.path("resolution").path("name").asText("");
                String author = root.path("user").path("displayName").asText("");
                String comment = root.path("comment").path("body").asText("");

                String resLower = resolution.toLowerCase(Locale.ROOT);
                boolean isFp = resLower.contains("false positive") || resLower.contains("cannot reproduce");
                boolean isWontFix = isFp || resLower.contains("won't fix") || resLower.contains("wontfix") || resLower.contains("declined") || resLower.contains("rejected");

                return new ExtractedTicketEvent(key, status, resolution, comment, author, isWontFix, isFp);
            }
            case SERVICENOW -> {
                String number = root.path("number").asText("");
                String sysId = root.path("sys_id").asText("");
                String state = root.path("state").asText("");
                String closeCode = root.path("close_code").asText("");
                String author = root.path("closed_by").asText("");
                String closeNotes = root.path("close_notes").asText("");

                String codeLower = closeCode.toLowerCase(Locale.ROOT);
                boolean isFp = codeLower.contains("false positive") || codeLower.contains("not an issue");
                boolean isWontFix = isFp || codeLower.contains("won't fix") || codeLower.contains("risk accepted") || codeLower.contains("withdrawn");

                return new ExtractedTicketEvent(number.isEmpty() ? sysId : number, state, closeCode, closeNotes, author, isWontFix, isFp);
            }
            default -> {
                return null;
            }
        }
    }
}
