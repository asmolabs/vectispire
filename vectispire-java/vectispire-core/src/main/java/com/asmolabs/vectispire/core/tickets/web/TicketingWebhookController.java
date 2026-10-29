package com.asmolabs.vectispire.core.tickets.web;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.tickets.TicketingWebhookService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
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
import org.springframework.web.server.ResponseStatusException;

/**
 * Inbound webhook endpoint for bidirectional issue tracking synchronization (Jira, GitLab, GitHub, ServiceNow).
 *
 * <p>The system's only anonymous door. What it may do once inside — and why a tracker's decision
 * goes to approval rather than settling — is {@link TicketingWebhookService}'s to say.
 *
 * <p><b>A refusal is a problem document, like every other refusal of the API</b> (RFC 9457): an
 * unknown provider, a body that is not JSON, a failed authentication, an unconfigured secret. They
 * were answered with the success body — {@code matched: false} and the sentence in {@code
 * actionTaken} — so an integration reading {@code detail} found nothing, and one reading the body
 * could not tell a refusal from a delivery that matched no issue but by the status. The sentence moved
 * to {@code detail}, unchanged; what a delivery that was read answers keeps its shape.
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

    /**
     * A refusal as the OpenAPI document describes it — never built: {@code ApiExceptionHandler} writes the
     * RFC 9457 problem. Spring's {@code ProblemDetail} as the schema would publish its extension map as a
     * nested {@code properties} member, which no answer carries.
     */
    @Schema(name = "WebhookRefusal", description = "A refused delivery: an RFC 9457 problem whose detail says why.")
    record Refusal(String type, String title, int status, String detail, String instance, String code) {}

    @Operation(
            summary = "Handle incoming ticketing webhook",
            description = "Receives webhook notifications from external issue trackers (Jira, GitLab, GitHub, ServiceNow) and synchronizes triage status.")
    @ApiResponse(responseCode = "200", description = "Webhook processed successfully")
    @ApiResponse(responseCode = "400", description = "Unsupported provider, or a body that is not JSON",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = Refusal.class)))
    @ApiResponse(responseCode = "401", description = "The delivery's token or signature was not accepted",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = Refusal.class)))
    @ApiResponse(responseCode = "403", description = "No webhook secret is configured on this instance",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = Refusal.class)))
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
            throw new InvalidInputException("Unsupported provider: " + providerStr);
        }

        TicketingWebhookService.Outcome outcome = webhooks.handle(
                provider.get(),
                rawPayload,
                new WebhookAuthenticity.Presented(gitlabToken, githubSignature, sharedToken),
                RequestActors.unnamed(request));

        return switch (outcome) {
            // No detail: a caller learning *which* header was wrong learns which tracker we expect.
            case TicketingWebhookService.Outcome.Rejected rejected ->
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Webhook authentication failed");
            // Said plainly: it lands in the tracker's delivery log, which is where whoever set up
            // the integration looks when triage stops arriving.
            case TicketingWebhookService.Outcome.NotConfigured notConfigured -> throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "The ticket webhook is not configured on this instance: an administrator has to set its secret first");
            case TicketingWebhookService.Outcome.Malformed malformed -> throw new InvalidInputException("Malformed JSON body");
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
