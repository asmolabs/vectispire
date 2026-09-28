package com.asmolabs.vectispire.core.agents.web;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.StoredFile;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAgentKey;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.agents.AgentProtocolService;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.scanning.ScanPlugins;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.List;
import java.util.Map;
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
 * <p>A handful of routes and one idea: an agent is a worker <b>with no database access</b>. It
 * announces itself and the key it receives credentials under, claims a task, fetches the rules the
 * task names, gives a sign of life while it works, and hands back its result. Everything it knows of
 * the control plane goes through these calls.
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

    private final AgentJobPoller poller;
    private final RuleSetService ruleSets;
    private final ScanPlugins plugins;
    private final AgentProtocolService protocol;

    public AgentsController(
            AgentJobPoller poller,
            RuleSetService ruleSets,
            ScanPlugins plugins,
            AgentProtocolService protocol) {
        this.poller = poller;
        this.ruleSets = ruleSets;
        this.plugins = plugins;
        this.protocol = protocol;
    }

    /**
     * @param sealingPublicKey still sent by every agent, for a control plane older than decision
     *     0031 that seals for it. <b>Read by nothing here</b>: it is unsigned, and a key the channel
     *     can rewrite is not one to seal for. The signed announcement is {@code POST /sealing-key}
     */
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
     * @param publicKey base64 of the X25519 SPKI encoding, as the agent generated it at start
     * @param generation when the agent made the pair, in epoch milliseconds
     * @param signature base64 Ed25519, by the agent's result-signing key — see {@code
     *     SealingKeyAttestation} for the exact bytes
     */
    public record SealingKeyRequest(@JsonProperty("public_key") String publicKey, Long generation, String signature) {}

    /**
     * The agent's sealing key, signed with the key an administrator pinned for it.
     *
     * <p>A route of its own rather than a field of the hello, because the signature covers the
     * agent's id and an agent learns its id from the hello's answer. <b>An older control plane
     * answers 404 here</b>, which the agent reads as "not supported" and carries on: its hello still
     * carries the unsigned key such a control plane seals for.
     *
     * <p>The answers are distinct because each has its own fix: 412 — no signing key is pinned for
     * this agent, an administrator's to do; 403 — the signature does not verify against the pinned
     * key, the agent's configuration; 409 — older than the key already accepted, a clock put back.
     * The two last are audited before the answer.
     */
    @PostMapping("/sealing-key")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void announceSealingKey(
            @RequestBody SealingKeyRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AgentView agent = authenticate(principal);
        AgentProtocolService.SealingKey outcome = protocol.announceSealingKey(
                agent,
                new AgentProtocolService.SealingKeyAnnouncement(body.publicKey(), body.generation(), body.signature()),
                RequestActors.unnamed(request));

        switch (outcome) {
            case AgentProtocolService.SealingKey.Accepted accepted -> {
                // 204: nothing to say back; the next claim seals for this key.
            }
            case AgentProtocolService.SealingKey.Unreadable unreadable -> throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "A sealing key announcement needs an X25519 public key, a positive generation and a signature.");
            case AgentProtocolService.SealingKey.NotPinned notPinned -> throw new ResponseStatusException(
                    HttpStatus.PRECONDITION_FAILED,
                    "No signing key is pinned for agent \"" + agent.name() + "\", so its sealing key cannot be "
                            + "verified and no credential will be delegated to it. Pin one from the agents "
                            + "administration screen and configure its private half as vectispire.agent.signing-key.");
            case AgentProtocolService.SealingKey.NotVerified notVerified -> throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "The sealing key's signature does not verify against the signing key pinned for \""
                            + agent.name() + "\". No credential will be sealed for it.");
            case AgentProtocolService.SealingKey.Stale stale -> throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This sealing key is older than the one already accepted for \"" + agent.name()
                            + "\". Check the agent's clock, or have an administrator reset its sealing key.");
        }
    }

    /**
     * An agent's announcement, and <b>an operator's first diagnostic</b>.
     *
     * <p>If this call answers, the URL, the key, the scope and the agent row are all correct —
     * that is, most of what can be misconfigured.
     */
    @PostMapping("/hello")
    public HelloResponse hello(@RequestBody HelloRequest body, @AuthenticationPrincipal VectispirePrincipal principal) {
        AgentView agent = authenticate(principal);
        AgentProtocolService.Hello answer = protocol.hello(agent, new AgentProtocolService.Announcement(
                body.contractVersion(),
                body.hostname(),
                body.platform(),
                body.version(),
                body.scannerEngine(),
                body.capabilities()));

        return switch (answer) {
            // 409 and not 400: the request is well formed, the two sides simply disagree about
            // the protocol — and the fix is a deployment, not another call.
            case AgentProtocolService.Hello.IncompatibleContract(String announced) -> throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This agent speaks contract \"" + (announced.isEmpty() ? "unknown" : announced)
                            + "\" and Vectispire speaks \"" + AgentContract.VERSION + "\". Update the agent.");
            case AgentProtocolService.Hello.Accepted(int maxConcurrent) -> new HelloResponse(
                    agent.id(),
                    agent.name(),
                    AgentContract.VERSION,
                    maxConcurrent,
                    agent.credentialsMode());
        };
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
        return ruleSets.contentByHash(hash)
                .map(content -> new RuleSetResponse(content.contentHash(), content.files()))
                .orElseThrow(() -> new NotFoundException("No rule set with hash " + hash + "."));
    }

    /**
     * A plugin's manifest, by the id and digest a task named.
     *
     * <p>The rule set's reasoning, for code: the task carries the reference, the agent fetches exactly
     * that manifest — the current one or an older one a queued task still names — and checks that it
     * hashes to the digest before running it. 404 for a reference no plugin ever had: the agent then
     * reports the plugin absent, never runs something else in its place.
     */
    @GetMapping("/plugins/{id}/{digest}")
    public PluginManifest plugin(
            @PathVariable String id, @PathVariable String digest, @AuthenticationPrincipal VectispirePrincipal principal) {
        authenticate(principal);
        return plugins.manifest(new PluginRef(id, digest))
                .orElseThrow(() -> new NotFoundException("No plugin " + id + " with manifest " + digest + "."));
    }

    /**
     * Claims a task, or answers 204 when the wait runs out.
     *
     * <p><b>Whether the link is encrypted no longer decides anything here.</b> A delegated
     * credential used to leave in the clear when the connection counted as encrypted; since decision
     * 0031 it leaves sealed for a key the agent proved, or not at all, and TLS is no substitute for
     * that — a proxy that terminates it reads what it carries.
     */
    @GetMapping("/jobs")
    public DeferredResult<ResponseEntity<Object>> claimJob(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "0") int wait) {

        AgentView agent = authenticate(principal);
        // **The refusal is not decided here.** It used to be, duplicating the same rule in the
        // dispatcher — and the two copies had already diverged. Only the dispatcher knows what
        // the task actually contains; it raises, and the handler turns that into a 412.
        return poller.claim(agent, Duration.ofSeconds(wait));
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
        AgentView agent = authenticate(principal);
        if (!protocol.renewLease(agent, scanId)) {
            // 409: the lease was taken over while the agent worked. It has to give up rather than
            // hand back a result that would overwrite its successor's.
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "This scan is no longer yours: its lease was taken over.");
        }
    }

    /**
     * The result of a scan executed elsewhere.
     *
     * <p><b>The attestation is checked, and it used to be checked nowhere.</b> This method has
     * always taken an {@code X-Vectispire-Agent-Signature} header, documented it as a
     * cryptographic attestation, and published it in the OpenAPI document — while never reading
     * the parameter, and while no agent ever produced one. An announced guarantee that does not
     * run is worse than an absent one: it is the reason nobody looked. The check itself is
     * {@link AgentProtocolService#submitResult}'s.
     *
     * <p><b>The body arrives as bytes, and that is what the signature covers.</b> The Swagger
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

        AgentView agent = authenticate(principal);
        AgentProtocolService.Submission outcome = protocol.submitResult(
                agent,
                scanId,
                body,
                signature,
                RequestActors.unnamed(request));

        return switch (outcome) {
            case AgentProtocolService.Submission.Accepted accepted -> Map.of("accepted", true);
            // 403 rather than 401: the API key was accepted, so re-authenticating changes nothing.
            // The refusal has already been audited, before this answer.
            case AgentProtocolService.Submission.NotAttested refused -> throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "This agent's results must be signed: the " + ResultAttestation.HEADER
                            + " header is absent or does not verify against the key pinned for \""
                            + agent.name() + "\".");
            // 400 and not 500: the agent sent something, and what it sent is the problem.
            case AgentProtocolService.Submission.Unreadable unreadable -> throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "The result body is not a readable ScanArtifacts document.");
            case AgentProtocolService.Submission.NoLongerYours discarded -> throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "This scan is no longer yours: its results were discarded.");
        };
    }

    /**
     * @param attempt the attempt the claim handed the agent — {@code AgentTask.attempt}
     * @param reason why the scan could not run, scrubbed by the agent and again on arrival
     */
    public record FailureReportRequest(Integer attempt, String reason) {}

    /**
     * @param retried back in the queue for another attempt; false when that was the last and the scan
     *     failed for good
     */
    public record FailureReportResponse(boolean retried, int attempt, int maxAttempts) {}

    /**
     * "I could not run this scan": the clone refused, the workspace not made, a credential that would
     * not open — anything before a result exists.
     *
     * <p><b>It used to be silence.</b> The agent dropped the scan, the lease took twenty minutes to
     * lapse, the reclaim spent an attempt on it, and the reason stayed in a log on another machine. The
     * report does what the lapse would have done, now, and leaves the reason on the scan.
     *
     * <p><b>Signed as a result is</b>, in the same header, under a context of its own; the body names
     * the attempt, so a report applies once and to that attempt alone. 409 for a scan that is not this
     * agent's at that attempt — which is also the answer to a report sent twice. <b>An older control
     * plane answers 404</b>, and the agent then leaves the lease to lapse, as before.
     */
    @PostMapping("/jobs/{scanId}/failure")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @io.swagger.v3.oas.annotations.media.Content(
                    schema = @io.swagger.v3.oas.annotations.media.Schema(implementation = FailureReportRequest.class)))
    public FailureReportResponse reportFailure(
            @PathVariable long scanId,
            @RequestBody byte[] body,
            @RequestHeader(name = ResultAttestation.HEADER, required = false) String signature,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AgentView agent = authenticate(principal);
        AgentProtocolService.FailureOutcome outcome =
                protocol.reportFailure(agent, scanId, body, signature, RequestActors.unnamed(request));

        return switch (outcome) {
            case AgentProtocolService.FailureOutcome.Recorded(boolean retried, int attempt, int maxAttempts) ->
                    new FailureReportResponse(retried, attempt, maxAttempts);
            case AgentProtocolService.FailureOutcome.NotAttested refused -> throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "This agent's reports must be signed: the " + ResultAttestation.HEADER
                            + " header is absent or does not verify against the key pinned for \""
                            + agent.name() + "\".");
            case AgentProtocolService.FailureOutcome.Unreadable unreadable -> throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "A failure report needs a JSON body naming the attempt, from 1.");
            case AgentProtocolService.FailureOutcome.NoLongerYours discarded -> throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This scan is not yours at that attempt: the report was already applied, or the lease was taken over.");
        };
    }

    private AgentView authenticate(VectispirePrincipal principal) {
        AgentView agent = principal == null
                ? null
                : principal.agent().orElse(null);
        if (agent == null) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "API key absent, invalid, or without the \"agent\" scope.");
        }
        if (!protocol.admits(agent)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Agent \"" + agent.name() + "\" is disabled.");
        }
        return agent;
    }
}
