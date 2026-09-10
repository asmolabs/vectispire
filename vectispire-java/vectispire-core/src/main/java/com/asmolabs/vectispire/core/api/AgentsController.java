package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.StoredFile;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.api.security.RequiresAgentKey;
import com.asmolabs.vectispire.core.api.security.TrustedProxies;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.services.RuleSetService;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.ScanDispatcher;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.server.ResponseStatusException;

/**
 * The remote agent protocol.
 *
 * <p>Four routes and one idea: an agent is a worker <b>with no database access</b>. It announces
 * itself, claims a task, gives a sign of life while it works, and hands back its result.
 * Everything it knows of the control plane goes through these four calls.
 *
 * <p><b>Outside the session rules does not mean open.</b> These routes carry no session because
 * an agent has none: it authenticates with an API key bearing the {@code agent} scope. The check
 * is made here, explicitly — forgetting it on one route would open the scan queue to whoever
 * knows the URL.
 */
@RestController
@RequestMapping("/api/v1/agent")
@RequiresAgentKey
public class AgentsController {

    private final ScanDispatcher dispatcher;
    private final AgentJobPoller poller;
    private final RuleSetService ruleSets;
    private final Agents agents;
    private final TrustedProxies proxies;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final Clock clock;

    public AgentsController(
            ScanDispatcher dispatcher,
            AgentJobPoller poller,
            RuleSetService ruleSets,
            Agents agents,
            TrustedProxies proxies,
            AuditLogService audit,
            ObjectMapper json,
            Clock clock) {
        this.dispatcher = dispatcher;
        this.poller = poller;
        this.ruleSets = ruleSets;
        this.agents = agents;
        this.proxies = proxies;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
    }

    public record HelloRequest(
            @JsonProperty("contract_version") String contractVersion,
            @JsonProperty("sealing_public_key") String sealingPublicKey,
            String hostname,
            String platform,
            String version,
            @JsonProperty("scanner_engine") String scannerEngine,
            String capabilities) {}

    public record HelloResponse(
            UUID id,
            String name,
            String contractVersion,
            int maxConcurrent,
            String credentialsMode) {}

    public record RuleSetResponse(String contentHash, List<StoredFile> files) {}

    /**
     * An agent's announcement, and <b>an operator's first diagnostic</b>.
     *
     * <p>If this call answers, the URL, the key, the scope and the agent row are all correct —
     * that is, most of what can be misconfigured.
     */
    @PostMapping("/hello")
    public HelloResponse hello(@RequestBody HelloRequest body, @AuthenticationPrincipal VectispirePrincipal principal) {
        AgentEntity agent = authenticate(principal);
        String announced = body.contractVersion() == null ? "" : body.contractVersion();

        if (!AgentContract.isCompatible(announced)) {
            // 409 and not 400: the request is well formed, the two sides simply disagree about
            // the protocol — and the fix is a deployment, not another call.
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This agent speaks contract \"" + (announced.isEmpty() ? "unknown" : announced)
                            + "\" and Vectispire speaks \"" + AgentContract.VERSION + "\". Update the agent.");
        }

        // **Refused when unusable, rather than stored as it stands.** An unreadable value would
        // raise in the middle of a claim; `null` simply drops this agent back to the earlier
        // behaviour — a clear key over an encrypted link — which is a degraded mode, not a
        // failure.
        String sealingKey = text(body.sealingPublicKey());
        if (sealingKey != null && !SealedEnvelope.isUsablePublicKey(sealingKey)) {
            throw new IllegalArgumentException("The announced sealing key is not a readable X25519 public key.");
        }

        agents.recordHeartbeat(
                agent.getId(),
                clock.instant(),
                text(body.hostname()),
                text(body.platform()),
                text(body.version()),
                text(body.scannerEngine()),
                text(body.capabilities()),
                announced,
                sealingKey);

        return new HelloResponse(
                agent.getId(),
                agent.getName(),
                AgentContract.VERSION,
                agent.getMaxConcurrent() == null ? 1 : agent.getMaxConcurrent(),
                agent.getCredentialsMode());
    }

    /**
     * A rule set's content, by its hash.
     *
     * <p><b>Fetched by hash and not as "the active set"</b>, and that is half the point: an agent
     * asking for the active set would get whatever is active <em>at that instant</em>, while its
     * task was built earlier. Two agents could then scan the same target with different rules —
     * exactly the divergence uploading rule sets removes.
     *
     * <p>Immutable by construction: a hash names a content, never a state, so an agent may cache
     * it with no invalidation.
     */
    @GetMapping("/rules/{hash}")
    public RuleSetResponse ruleSet(@PathVariable String hash, @AuthenticationPrincipal VectispirePrincipal principal) {
        authenticate(principal);
        // 404 rather than an empty set: the agent must fail its SAST step, not scan with the
        // bundled rules alone and hand back a shorter list that reads as "analyzed, these issues
        // are gone".
        return ruleSets.byHash(hash)
                .map(set -> new RuleSetResponse(set.getContentHash(), ruleSets.filesOf(set)))
                .orElseThrow(() -> new NoSuchElementException("No rule set with hash " + hash + "."));
    }

    /**
     * Claims a task, or answers 204 when the wait runs out.
     *
     * <p><b>Whether the link counts as encrypted is not this route's to decide.</b> It used to
     * read {@code X-Forwarded-Proto} from any peer, which meant an attacker holding an agent key
     * could ask for the deployment key in the clear by sending one header. {@link TrustedProxies}
     * now answers that question, and it answers {@code false} unless the connection really is
     * encrypted or the peer is a proxy the operator declared.
     */
    @GetMapping("/jobs")
    public DeferredResult<ResponseEntity<Object>> claimJob(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "0") int wait,
            HttpServletRequest request) {

        AgentEntity agent = authenticate(principal);
        // **The refusal is not decided here.** It used to be, duplicating the same rule in the
        // dispatcher — and the two copies had already diverged. Only the dispatcher knows what
        // the task actually contains; it raises, and the handler turns that into a 412.
        return poller.claim(agent, proxies.isSecureTransport(request), Duration.ofSeconds(wait));
    }

    /**
     * The sign of life of an agent still working.
     *
     * <p>It is what tells "slow" from "dead": without it a twenty-minute scan would see its lease
     * lapse and be taken over by another worker, which would redo the same work while the first
     * one finishes it.
     */
    @PostMapping("/jobs/{scanId}/heartbeat")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void heartbeat(@PathVariable long scanId, @AuthenticationPrincipal VectispirePrincipal principal) {
        AgentEntity agent = authenticate(principal);
        if (!dispatcher.renewAgentLease(scanId, agent)) {
            // 409: the lease was taken over while the agent worked. It has to give up rather than
            // hand back a result that would overwrite its successor's.
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "This scan is no longer yours: its lease was taken over.");
        }
    }

    /**
     * The result of a scan executed elsewhere.
     *
     * <p><b>The attestation is checked here, and it used to be checked nowhere.</b> This method
     * has always taken an {@code X-Vectispire-Agent-Signature} header, documented it as a
     * cryptographic attestation, and published it in the OpenAPI document — while never reading
     * the parameter, and while no agent ever produced one. An announced guarantee that does not
     * run is worse than an absent one: it is the reason nobody looked.
     *
     * <p>What it guards is the operation described in {@link ResultAttestation}: artifacts that
     * are present and empty resolve a target's whole backlog of that type. An agent with a pinned
     * signing key must now prove it is that agent; an agent without one behaves exactly as before.
     *
     * <p><b>The body arrives as bytes, and that is what the signature covers.</b> Parsing first
     * and signing the re-serialization would sign what the server chose to write. The Swagger
     * annotation restores the schema the raw type erases, so the published contract still says
     * {@link ScanArtifacts}.
     */
    @PostMapping("/jobs/{scanId}/result")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @io.swagger.v3.oas.annotations.media.Content(
                    schema = @io.swagger.v3.oas.annotations.media.Schema(implementation = ScanArtifacts.class)))
    public Map<String, Boolean> submitResult(
            @PathVariable long scanId,
            @RequestBody byte[] body,
            @RequestHeader(name = ResultAttestation.HEADER, required = false) String signature,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AgentEntity agent = authenticate(principal);
        requireAttestation(agent, scanId, body, signature, request);

        ScanArtifacts artifacts;
        try {
            artifacts = json.readValue(body, ScanArtifacts.class);
        } catch (java.io.IOException unreadable) {
            // 400 and not 500: the agent sent something, and what it sent is the problem.
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "The result body is not a readable ScanArtifacts document.");
        }

        if (!dispatcher.acceptAgentResult(scanId, agent, artifacts)) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "This scan is no longer yours: its results were discarded.");
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_RESULT_SUBMITTED,
                String.valueOf(scanId),
                "Result accepted from agent \"" + agent.getName() + "\""
                        + (agent.getSigningPublicKey() == null ? " (not attested)." : ", attestation verified."),
                agent.getName(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("accepted", true);
    }

    /**
     * Refuses a result that a pinned key does not vouch for.
     *
     * <p><b>Pinning the key is the switch.</b> There is no second setting saying "and now enforce
     * it" — an operator who writes the key has said what they mean, and a control with an
     * enforcement flag of its own is a control somebody leaves in audit mode for a year.
     *
     * <p>403 rather than 401: the API key was accepted, so re-authenticating changes nothing. The
     * refusal is audited before it is thrown, because a probe that leaves no trace is the one
     * nobody investigates.
     */
    private void requireAttestation(
            AgentEntity agent, long scanId, byte[] body, String signature, HttpServletRequest request) {

        String pinned = agent.getSigningPublicKey();
        if (pinned == null || pinned.isBlank()) {
            return;
        }
        if (ResultAttestation.verify(pinned, scanId, body, signature)) {
            return;
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_RESULT_REFUSED,
                String.valueOf(scanId),
                (signature == null || signature.isBlank()
                                ? "Result submitted with no attestation"
                                : "Result submitted with an attestation that does not verify")
                        + " by agent \"" + agent.getName() + "\", whose signing key is pinned.",
                agent.getName(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "This agent's results must be signed: the " + ResultAttestation.HEADER
                        + " header is absent or does not verify against the key pinned for \""
                        + agent.getName() + "\".");
    }

    private static AgentEntity authenticate(VectispirePrincipal principal) {
        AgentEntity agent = principal == null
                ? null
                : principal.agent().orElse(null);
        if (agent == null) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "API key absent, invalid, or without the \"agent\" scope.");
        }
        if (!agent.getEnabled()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Agent \"" + agent.getName() + "\" is disabled.");
        }
        return agent;
    }

    private static String text(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
