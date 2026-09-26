package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.access.AgentView;
import com.asmolabs.vectispire.core.services.agents.AgentAdministrationService;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administering agents — separate from the protocol they speak.
 *
 * <p>Two controllers and not one: this one needs an administrator's session, the other an
 * agent's API key. Merging them would mean one annotation mistake on one route opens either the
 * administration to agents or the queue to an ordinary session.
 */
@RestController
@RequestMapping("/api/v1/admin/agents")
@RequiresAdministrator
public class AgentsAdminController {

    private final AgentAdministrationService administration;

    public AgentsAdminController(AgentAdministrationService administration) {
        this.administration = administration;
    }

    /**
     * @param sealsCredentials whether this agent announced what it takes to receive a sealed
     *     secret. <b>The public key itself is not exposed</b>: it tells an operator nothing, and
     *     one more opaque value on a screen helps nobody. This boolean does — an operator who
     *     believes they are sealing while their agent is an older version would have no other
     *     way to notice, and the deployment key would cross their proxy in the clear
     * @param signsResults whether a result-signing key is pinned for this agent — that is,
     *     whether a stolen API key would be enough to declare this agent's targets clean. The
     *     public key is not exposed for the same reason the sealing one is not: the operator needs
     *     the answer, not the value
     * @param online seen recently, not "enabled". An enabled agent that has been silent for an
     *     hour is the case that matters: the queue fills, nobody drains it, and nothing else on
     *     the screen would say so
     */
    public record AgentSummary(
            UUID id,
            String name,
            String description,
            String kind,
            boolean enabled,
            String credentialsMode,
            String labels,
            boolean sealsCredentials,
            boolean signsResults,
            int maxConcurrent,
            String hostname,
            String platform,
            String version,
            String contractVersion,
            Instant lastSeenAt,
            boolean online,
            long runningScans) {}

    public record AgentCreateRequest(
            String name,
            String description,
            @JsonProperty("credentials_mode") String credentialsMode,
            String labels,
            @JsonProperty("max_concurrent") Integer maxConcurrent) {}

    public record AgentUpdateRequest(
            Boolean enabled, String labels, @JsonProperty("max_concurrent") Integer maxConcurrent) {}

    /** @param secret the only occurrence of the plaintext key. It will never appear again */
    public record DeclaredAgent(UUID id, String name, String secret) {}

    public record UnroutableLabel(String label, long queued) {}

    public record RunningScanItem(
            Long scanId,
            String targetType,
            Long targetId,
            String targetName,
            String branch,
            String agentId,
            String agentName,
            Instant claimedAt,
            long durationSeconds,
            String requiredLabel) {}

    public record PendingScanItem(
            Long scanId,
            String targetType,
            Long targetId,
            String targetName,
            String branch,
            String requiredLabel,
            Instant queuedAt,
            long waitDurationSeconds,
            boolean isRoutable,
            int positionInQueue) {}

    public record QueueStats(
            int totalAgents,
            int onlineAgents,
            int busyAgents,
            int idleAgents,
            long runningScansCount,
            long pendingScansCount,
            long scansCompleted24h,
            long avgScanDurationSeconds) {}

    public record AgentActivitySummary(
            List<RunningScanItem> runningScans,
            List<PendingScanItem> pendingScans,
            QueueStats stats) {}

    @GetMapping("/activity")
    public AgentActivitySummary activity() {
        AgentAdministrationService.Activity activity = administration.activity();
        AgentAdministrationService.QueueFigures figures = activity.figures();
        return new AgentActivitySummary(
                activity.running().stream()
                        .map(scan -> new RunningScanItem(
                                scan.scanId(),
                                scan.targetType(),
                                scan.targetId(),
                                scan.targetName(),
                                scan.branch(),
                                scan.agentId(),
                                scan.agentName(),
                                scan.claimedAt(),
                                scan.durationSeconds(),
                                scan.requiredLabel()))
                        .toList(),
                activity.pending().stream()
                        .map(scan -> new PendingScanItem(
                                scan.scanId(),
                                scan.targetType(),
                                scan.targetId(),
                                scan.targetName(),
                                scan.branch(),
                                scan.requiredLabel(),
                                scan.queuedAt(),
                                scan.waitDurationSeconds(),
                                scan.routable(),
                                scan.positionInQueue()))
                        .toList(),
                new QueueStats(
                        figures.totalAgents(),
                        figures.onlineAgents(),
                        figures.busyAgents(),
                        figures.idleAgents(),
                        figures.runningScansCount(),
                        figures.pendingScansCount(),
                        figures.scansCompleted24h(),
                        figures.avgScanDurationSeconds()));
    }

    @GetMapping
    public List<AgentSummary> list() {
        return administration.list().stream()
                .map(view -> {
                    AgentView agent = view.agent();
                    return new AgentSummary(
                            agent.id(),
                            agent.name(),
                            agent.description(),
                            agent.kind(),
                            agent.enabled(),
                            agent.credentialsMode(),
                            agent.labels(),
                            agent.sealingPublicKey() != null,
                            agent.signingPublicKey() != null,
                            view.maxConcurrent(),
                            agent.hostname(),
                            agent.platform(),
                            agent.version(),
                            agent.contractVersion(),
                            agent.lastSeenAt(),
                            view.online(),
                            view.runningScans());
                })
                .toList();
    }

    /** Declares an agent and issues its key — see {@link AgentAdministrationService#declare}. */
    @PostMapping
    public DeclaredAgent create(
            @RequestBody AgentCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AgentAdministrationService.Declared declared = administration.declare(
                new AgentAdministrationService.Declaration(
                        body.name(), body.description(), body.credentialsMode(), body.labels(), body.maxConcurrent()),
                RequestActors.of(principal, request));
        return new DeclaredAgent(declared.agent().id(), declared.agent().name(), declared.secret());
    }

    /** Enables or disables. A disabled agent claims nothing, without losing its history. */
    @PatchMapping("/{id}")
    public Map<String, Object> update(
            @PathVariable UUID id,
            @RequestBody AgentUpdateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AgentAdministrationService.Changed changed = administration.change(
                id,
                new AgentAdministrationService.Change(body.enabled(), body.labels(), body.maxConcurrent()),
                RequestActors.of(principal, request));

        Map<String, Object> answer = new HashMap<>();
        answer.put("id", changed.id());
        answer.put("enabled", changed.enabled());
        answer.put("labels", changed.labels());
        return answer;
    }

    /** @param publicKey base64 Ed25519, or null/blank to stop requiring signed results */
    public record SigningKeyRequest(@JsonProperty("public_key") String publicKey) {}

    /**
     * @param privateKey the half to put in the agent's configuration, shown once. Null when the
     *     operator supplied their own public key, because then the control plane never held it
     */
    public record PinnedSigningKey(UUID id, boolean signsResults, String privateKey) {}

    /**
     * Pins the key an agent's results must be signed with — or removes it.
     *
     * <p><b>This route is the reason the attestation is worth checking.</b> The signing key
     * arrives here, over an administrator's session, and never over the agent protocol: a key the
     * agent announced would prove nothing its API key had not already proved. See
     * {@link ResultAttestation}.
     *
     * <p><b>The pair may be generated here, and that is a deliberate convenience with a cost.</b>
     * Sending no {@code public_key} makes the control plane generate a pair, keep the public half
     * and return the private one once — which means the private half existed here for the length
     * of one response. An operator who would rather it never did generates the pair themselves
     * and sends only the public half; both paths are supported and the answer says which one ran.
     */
    @PutMapping("/{id}/signing-key")
    public PinnedSigningKey pinSigningKey(
            @PathVariable UUID id,
            @RequestBody SigningKeyRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AgentAdministrationService.PinnedKey pinned = administration.pinSigningKey(
                id, body == null ? null : body.publicKey(), RequestActors.of(principal, request));
        return new PinnedSigningKey(pinned.id(), pinned.signsResults(), pinned.privateKey());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        administration.remove(id, RequestActors.of(principal, request));
    }

    /**
     * The scans <b>nobody</b> can take, grouped by the label they require.
     *
     * <p><b>Without this screen the wait is silent.</b> A target labelled {@code customer} when
     * no enabled agent carries that label queues its scans, where they stay for ever: the
     * repositories page says "waiting", which is true and useless, and nothing names the cause.
     */
    @GetMapping("/non-routables")
    public List<UnroutableLabel> unroutable() {
        return administration.unroutable().stream()
                .map(label -> new UnroutableLabel(label.label(), label.queued()))
                .toList();
    }
}
