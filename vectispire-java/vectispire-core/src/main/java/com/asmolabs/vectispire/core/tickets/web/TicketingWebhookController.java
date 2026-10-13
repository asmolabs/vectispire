package com.asmolabs.vectispire.core.tickets.web;

import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.tickets.TicketingWebhookService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Inbound webhook endpoint for bidirectional issue tracking synchronization (Jira, GitLab, GitHub, ServiceNow).
 *
 * <p>The system's only anonymous door. What it may do once inside — and why a tracker's decision
 * goes to approval rather than settling — is {@link TicketingWebhookService}'s to say.
 */
@Tag(name = "Ticketing", description = "Issue tracker synchronization (Jira, GitLab, GitHub, ServiceNow)")
@RestController
@RequestMapping("/api/v1/tickets")
public class TicketingWebhookController {

    private final TicketingWebhookService webhooks;

    public TicketingWebhookController(TicketingWebhookService webhooks) {
        this.webhooks = webhooks;
    }

    /**
     * @param issueId the first issue carrying the reference — kept for the integrations that read it
     * @param issueIds every issue carrying it, oldest first: one ticket may stand for several findings
     */
    public record WebhookSyncResult(boolean matched, Long issueId, List<Long> issueIds, String ticketRef, String actionTaken) {

        static WebhookSyncResult unmatched(String ticketRef, String actionTaken) {
            return new WebhookSyncResult(false, null, List.of(), ticketRef, actionTaken);
        }
    }

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

        Optional<TicketProvider> provider = TicketProvider.fromWireName(providerStr);
        if (provider.isEmpty()) {
            return ResponseEntity.badRequest().body(WebhookSyncResult.unmatched(null, "Unsupported provider: " + providerStr));
        }

        TicketingWebhookService.Outcome outcome = webhooks.handle(
                provider.get(),
                rawPayload,
                new WebhookAuthenticity.Presented(gitlabToken, githubSignature, sharedToken),
                RequestActors.unnamed(request));

        return switch (outcome) {
            // No detail: a caller learning *which* header was wrong learns which tracker we expect.
            case TicketingWebhookService.Outcome.Rejected rejected -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(WebhookSyncResult.unmatched(null, "Webhook authentication failed"));
            // Said plainly: it lands in the tracker's delivery log, which is where whoever set up
            // the integration looks when triage stops arriving.
            case TicketingWebhookService.Outcome.NotConfigured notConfigured -> ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(WebhookSyncResult.unmatched(null,
                            "The ticket webhook is not configured on this instance: an administrator has to set its secret first"));
            case TicketingWebhookService.Outcome.Malformed malformed ->
                    ResponseEntity.badRequest().body(WebhookSyncResult.unmatched(null, "Malformed JSON body"));
            // 200: the tracker's own redelivery lands here too, and an error would make it retry.
            case TicketingWebhookService.Outcome.AlreadyProcessed seen ->
                    ResponseEntity.ok(WebhookSyncResult.unmatched(null, "Delivery already processed"));
            case TicketingWebhookService.Outcome.NoReference none ->
                    ResponseEntity.ok(WebhookSyncResult.unmatched(null, "No ticket reference extracted from payload"));
            case TicketingWebhookService.Outcome.NoMatchingIssue(String ticketRef) ->
                    ResponseEntity.ok(WebhookSyncResult.unmatched(ticketRef, "No matching Vectispire issue found"));
            case TicketingWebhookService.Outcome.Synced(List<Long> issueIds, String ticketRef, String actionTaken) ->
                    ResponseEntity.ok(new WebhookSyncResult(true, issueIds.getFirst(), issueIds, ticketRef, actionTaken));
        };
    }
}
