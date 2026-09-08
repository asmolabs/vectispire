package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.api.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.IssueTriageService;
import com.asmolabs.vectispire.core.services.SettingsService;
import com.asmolabs.vectispire.core.services.TicketService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Inbound webhook endpoint for bidirectional issue tracking synchronization (Jira, GitLab, GitHub, ServiceNow).
 */
@Tag(name = "Ticketing", description = "Issue tracker synchronization (Jira, GitLab, GitHub, ServiceNow)")
@RestController
@RequestMapping("/api/v1/tickets")
public class TicketingWebhookController {

    private static final Logger log = LoggerFactory.getLogger(TicketingWebhookController.class);

    private final Issues issues;
    private final IssueTriageService triageService;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final Clock clock;
    private final SettingsService settings;
    private final TicketService tickets;

    public TicketingWebhookController(
            Issues issues,
            IssueTriageService triageService,
            AuditLogService audit,
            ObjectMapper json,
            Clock clock,
            SettingsService settings,
            TicketService tickets) {
        this.issues = issues;
        this.triageService = triageService;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
        this.settings = settings;
        this.tickets = tickets;
    }

    public record WebhookSyncResult(boolean matched, Long issueId, String ticketRef, String actionTaken) {}

    @Operation(
            summary = "Handle incoming ticketing webhook",
            description = "Receives webhook notifications from external issue trackers (Jira, GitLab, GitHub, ServiceNow) and synchronizes triage status.")
    @ApiResponse(responseCode = "200", description = "Webhook processed successfully")
    @OpenToAnonymous
    @PostMapping(value = "/webhook/{provider}", consumes = {"application/json", "application/*+json", "*/*"})
    public ResponseEntity<WebhookSyncResult> handleWebhook(
            @Parameter(description = "Ticketing provider: jira, gitlab, github, servicenow", required = true)
            @PathVariable("provider") String providerStr,
            @RequestBody String rawPayload,
            @RequestHeader(name = "X-Gitlab-Token", required = false) String gitlabToken,
            @RequestHeader(name = "X-Hub-Signature-256", required = false) String githubSignature,
            @RequestHeader(name = "X-Vectispire-Token", required = false) String sharedToken,
            HttpServletRequest request) {

        Optional<TicketProvider> providerOpt = TicketProvider.fromWireName(providerStr);
        if (providerOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(new WebhookSyncResult(false, null, null, "Unsupported provider: " + providerStr));
        }

        TicketProvider provider = providerOpt.get();

        // **La seule porte anonyme du système, et elle ne clôt plus rien.** Elle ne peut pas
        // exiger de session — l'appelant est le tracker — et sans secret configuré elle reste
        // ouverte, parce que la fermer d'un coup arrêterait la synchronisation de tous les
        // déploiements existants sans que personne ne s'en aperçoive.
        //
        // Ce qui a changé est ce qu'elle peut faire une fois entrée. Elle proposait un triage qui
        // se réglait sur-le-champ ; elle en propose un qui part en approbation. Le secret reste
        // ce qui sépare le tracker de quiconque a deviné une référence de ticket, et il reste
        // vivement recommandé — mais il n'est plus la seule chose entre un inconnu et un
        // « non affecté » dans un document signé.
        WebhookAuthenticity.Verdict verdict = WebhookAuthenticity.verify(
                provider,
                // Decrypted, not read raw: the row now holds a ciphertext. Comparing the presented
                // token against the stored blob would refuse every legitimate call, and the
                // rejection reads exactly like an attacker probing.
                tickets.webhookSecret(),
                new WebhookAuthenticity.Presented(gitlabToken, githubSignature, sharedToken),
                rawPayload);
        if (verdict == WebhookAuthenticity.Verdict.REJECTED) {
            // Audited, because a stream of these is somebody probing and the audit log is where
            // that becomes visible. No detail in the response: a caller learning *which* header
            // was wrong learns which tracker we expect.
            audit.record(AuditLogService.Record.of(
                    AuditOperation.LOGIN_BLOCKED,
                    "ticket_webhook",
                    "Rejected unsigned or wrongly signed " + provider + " webhook from "
                            + request.getRemoteAddr(),
                    "anonymous"));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new WebhookSyncResult(false, null, null, "Webhook authentication failed"));
        }

        JsonNode payload;
        try {
            payload = json.readTree(rawPayload);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new WebhookSyncResult(false, null, null, "Malformed JSON body"));
        }

        ExtractedTicketEvent event = extractEvent(provider, payload);

        if (event == null || event.ticketRef() == null || event.ticketRef().isBlank()) {
            return ResponseEntity.ok(new WebhookSyncResult(false, null, null, "No ticket reference extracted from payload"));
        }

        Optional<IssueEntity> matchingIssue = issues.findByTicketRefOrIid(event.ticketRef());
        if (matchingIssue.isEmpty()) {
            log.info("Received webhook for ticket {} from {} but no corresponding Vectispire issue found.", event.ticketRef(), provider);
            return ResponseEntity.ok(new WebhookSyncResult(false, null, event.ticketRef(), "No matching Vectispire issue found"));
        }

        IssueEntity issue = matchingIssue.get();
        String actionTaken;

        if (event.isRefusedOrFalsePositive()) {
            TriageStatus status = TriageStatus.NOT_AFFECTED;
            VexJustification justification = event.isFalsePositive()
                    ? VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
                    : VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;

            // **L'auteur est l'intégration, et le nom revendiqué descend dans le commentaire.**
            // Il venait de la charge utile : sur une route anonyme, cela laissait l'appelant
            // choisir le nom que le journal d'audit — inviolable, jamais purgé — allait sceller
            // à côté de sa décision. La chaîne de hachage protège l'entrée d'une modification
            // ultérieure ; elle ne protège pas d'un mensonge qu'on lui a dicté. Le nom reste
            // utile et reste écrit, mais comme une donnée rapportée et non comme une identité.
            String author = provider.name() + "_webhook";
            String claimed = event.author() != null && !event.author().isBlank()
                    ? " (annoncé par le tracker comme : " + event.author() + ")"
                    : "";
            String comment = (event.comment() != null && !event.comment().isBlank()
                    ? event.comment()
                    : "Status updated from " + provider.name() + " ticket " + event.ticketRef())
                    + claimed;

            // **`false`, et c'est tout le correctif.** Ce booléen valait `true` : la décision d'un
            // tracker clôturait sur-le-champ, contournant la double validation. Sur une route qui
            // n'exige aucune authentification tant qu'aucun secret n'est configuré — le défaut —
            // cela signifiait qu'un POST anonyme pouvait poser `not_affected` avec la
            // justification `vulnerable_code_not_in_execute_path`, laquelle part telle quelle dans
            // les documents CycloneDX, OpenVEX et CSAF signés remis aux clients.
            //
            // C'est l'affirmation que ce dépôt a déjà retirée une fois : l'analyseur
            // d'atteignabilité a été rendu unidirectionnel pour qu'aucune machine ne vide un
            // composant sans humain, et `CycloneDxGeneratorService.mapAnalysis` réécrit
            // l'invariant en toutes lettres — « le triage vide un composant ; l'atteignabilité,
            // non ». Cette porte était le trou dedans : ni un humain, ni authentifiée.
            //
            // **Rien ne casse.** `queueIfNotApprover` convertit la décision en
            // `PENDING_APPROVAL` sans consulter le réglage de double validation, et
            // `pending_approval` se rend « en cours d'examen » dans les documents, jamais
            // « non affecté ». La synchronisation continue donc d'enregistrer ce que le tracker
            // dit ; elle cesse seulement de le publier à la place d'un humain.
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
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        } else {
            actionTaken = "Ticket updated on " + provider.name() + " (status: " + event.status() + ")";
            audit.record(new AuditLogService.Record(
                    AuditOperation.TICKET_SYNCED,
                    String.valueOf(issue.getId()),
                    "Ticket update received from " + provider.name() + " for " + event.ticketRef() + " (status: " + event.status() + ")",
                    event.author(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        }

        return ResponseEntity.ok(new WebhookSyncResult(true, issue.getId(), event.ticketRef(), actionTaken));
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
