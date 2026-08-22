package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.agents.AgentContract;
import com.asmolabs.zanshin.common.domain.crypto.SealedEnvelope;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.StoredFile;
import com.asmolabs.zanshin.common.scanning.ScanArtifacts;
import com.asmolabs.zanshin.core.api.security.RequiresAgentKey;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.AgentEntity;
import com.asmolabs.zanshin.core.repositories.Agents;
import com.asmolabs.zanshin.core.services.RuleSetService;
import com.asmolabs.zanshin.core.services.ScanDispatcher;
import com.fasterxml.jackson.annotation.JsonProperty;
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
    private final Clock clock;

    public AgentsController(
            ScanDispatcher dispatcher,
            AgentJobPoller poller,
            RuleSetService ruleSets,
            Agents agents,
            Clock clock) {
        this.dispatcher = dispatcher;
        this.poller = poller;
        this.ruleSets = ruleSets;
        this.agents = agents;
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
    public HelloResponse hello(@RequestBody HelloRequest body, @AuthenticationPrincipal ZanshinPrincipal principal) {
        AgentEntity agent = authenticate(principal);
        String announced = body.contractVersion() == null ? "" : body.contractVersion();

        if (!AgentContract.isCompatible(announced)) {
            // 409 and not 400: the request is well formed, the two sides simply disagree about
            // the protocol — and the fix is a deployment, not another call.
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This agent speaks contract \"" + (announced.isEmpty() ? "unknown" : announced)
                            + "\" and Zanshin speaks \"" + AgentContract.VERSION + "\". Update the agent.");
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
    public RuleSetResponse ruleSet(@PathVariable String hash, @AuthenticationPrincipal ZanshinPrincipal principal) {
        authenticate(principal);
        // 404 rather than an empty set: the agent must fail its SAST step, not scan with the
        // bundled rules alone and hand back a shorter list that reads as "analyzed, these issues
        // are gone".
        return ruleSets.byHash(hash)
                .map(set -> new RuleSetResponse(set.getContentHash(), ruleSets.filesOf(set)))
                .orElseThrow(() -> new NoSuchElementException("No rule set with hash " + hash + "."));
    }

    /** Claims a task, or answers 204 when the wait runs out. */
    @GetMapping("/jobs")
    public DeferredResult<ResponseEntity<Object>> claimJob(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @RequestHeader(name = "X-Forwarded-Proto", required = false) String forwardedProto,
            @RequestParam(required = false, defaultValue = "0") int wait,
            HttpServletRequest request) {

        AgentEntity agent = authenticate(principal);
        // **The refusal is not decided here.** It used to be, duplicating the same rule in the
        // dispatcher — and the two copies had already diverged. Only the dispatcher knows what
        // the task actually contains; it raises, and the handler turns that into a 412.
        return poller.claim(agent, isSecureTransport(request, forwardedProto), Duration.ofSeconds(wait));
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
    public void heartbeat(@PathVariable long scanId, @AuthenticationPrincipal ZanshinPrincipal principal) {
        AgentEntity agent = authenticate(principal);
        if (!dispatcher.renewAgentLease(scanId, agent)) {
            // 409: the lease was taken over while the agent worked. It has to give up rather than
            // hand back a result that would overwrite its successor's.
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "This scan is no longer yours: its lease was taken over.");
        }
    }

    /** The result of a scan executed elsewhere, with optional cryptographic attestation signature. */
    @PostMapping("/jobs/{scanId}/result")
    public Map<String, Boolean> submitResult(
            @PathVariable long scanId,
            @RequestBody ScanArtifacts artifacts,
            @RequestHeader(name = "X-Zanshin-Agent-Signature", required = false) String signature,
            @AuthenticationPrincipal ZanshinPrincipal principal) {

        AgentEntity agent = authenticate(principal);
        if (!dispatcher.acceptAgentResult(scanId, agent, artifacts)) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "This scan is no longer yours: its results were discarded.");
        }
        return Map.of("accepted", true);
    }

    private static AgentEntity authenticate(ZanshinPrincipal principal) {
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

    /**
     * Did this request arrive over an encrypted link?
     *
     * <p>{@code X-Forwarded-Proto} is honoured because the intended deployment puts a reverse
     * proxy in front, where the application only ever sees HTTP. <b>That header is trivially
     * forged</b> by anybody who can reach this port directly — which is why it decides exactly
     * one thing: whether a deployment key may travel. A decision the operator has already had to
     * make agent by agent.
     */
    private static boolean isSecureTransport(HttpServletRequest request, String forwardedProto) {
        if (forwardedProto != null && "https".equalsIgnoreCase(forwardedProto.split(",")[0].trim())) {
            return true;
        }
        return request.isSecure();
    }

    private static String text(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
