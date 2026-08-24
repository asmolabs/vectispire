package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.agents.AgentKind;
import com.asmolabs.zanshin.common.domain.agents.AgentLabels;
import com.asmolabs.zanshin.common.domain.agents.CredentialsMode;
import com.asmolabs.zanshin.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.zanshin.common.domain.apikeys.ApiKeys;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.AgentEntity;
import com.asmolabs.zanshin.core.persistence.ApiKeyEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Agents;
import com.asmolabs.zanshin.core.repositories.ApiKeysRepository;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.WorkerProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import com.asmolabs.zanshin.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GitRepositories;

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

    /** Past this without a word, an agent counts as offline. */
    private static final Duration ONLINE_TTL = Duration.ofSeconds(120);

    private final Agents agents;
    private final ApiKeysRepository keys;
    private final Scans scans;
    private final GitRepositories gitRepositories;
    private final Containers containers;
    private final AuditLogService audit;
    private final WorkerProperties worker;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public AgentsAdminController(
            Agents agents,
            ApiKeysRepository keys,
            Scans scans,
            GitRepositories gitRepositories,
            Containers containers,
            AuditLogService audit,
            WorkerProperties worker,
            TransactionTemplate transactions,
            Clock clock) {
        this.agents = agents;
        this.keys = keys;
        this.scans = scans;
        this.gitRepositories = gitRepositories;
        this.containers = containers;
        this.audit = audit;
        this.worker = worker;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * @param sealsCredentials whether this agent announced what it takes to receive a sealed
     *     secret. <b>The public key itself is not exposed</b>: it tells an operator nothing, and
     *     one more opaque value on a screen helps nobody. This boolean does — an operator who
     *     believes they are sealing while their agent is an older version would have no other
     *     way to notice, and the deployment key would cross their proxy in the clear
     * @param online seen recently, not "enabled". An enabled agent that has been silent for an
     *     hour is the case that matters: the queue fills, nobody drains it, and nothing else on
     *     the screen would say so
     */
    public record Summary(
            UUID id,
            String name,
            String description,
            String kind,
            boolean enabled,
            String credentialsMode,
            String labels,
            boolean sealsCredentials,
            Integer maxConcurrent,
            String hostname,
            String platform,
            String version,
            String contractVersion,
            Instant lastSeenAt,
            boolean online,
            long runningScans) {}

    public record CreateRequest(
            String name,
            String description,
            @JsonProperty("credentials_mode") String credentialsMode,
            String labels,
            @JsonProperty("max_concurrent") Integer maxConcurrent) {}

    public record UpdateRequest(
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
        Instant asOf = clock.instant();
        Instant last24h = asOf.minus(Duration.ofHours(24));

        List<AgentEntity> allAgents = agents.findAllByOrderByNameAsc();
        Map<String, String> agentNames = new HashMap<>();
        Set<String> activeAgentLabels = new HashSet<>();
        int onlineCount = 0;

        for (AgentEntity a : allAgents) {
            agentNames.put(a.getId().toString(), a.getName());
            if (isOnline(a, asOf)) {
                onlineCount++;
                if (Boolean.TRUE.equals(a.getEnabled())) {
                    activeAgentLabels.addAll(AgentLabels.parse(a.getLabels()));
                }
            }
        }
        activeAgentLabels.addAll(AgentLabels.parse(worker.labels()));

        Map<Long, String> repoNames = new HashMap<>();
        gitRepositories.findAll().forEach(r -> {
            String name = r.getName() != null && !r.getName().isBlank() ? r.getName() : r.getUrl();
            repoNames.put(r.getId(), name != null ? name : "Repo #" + r.getId());
        });

        Map<Long, String> containerNames = new HashMap<>();
        containers.findAll().forEach(c -> {
            String name = c.getImageName() + (c.getTag() != null && !c.getTag().isBlank() ? ":" + c.getTag() : "");
            containerNames.put(c.getId(), name);
        });

        List<ScanEntity> activeScans = scans.findByStatusInOrderByCreatedAtAsc(
                List.of(ScanStatus.SCANNING.wireName(), ScanStatus.PENDING.wireName()));

        List<RunningScanItem> runningItems = new ArrayList<>();
        List<PendingScanItem> pendingItems = new ArrayList<>();
        Set<String> busyAgentIds = new HashSet<>();
        int pendingPos = 1;

        for (ScanEntity scan : activeScans) {
            String targetType = scan.getRepoId() != null ? "repository" : "container";
            Long targetId = scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId();
            String targetName = scan.getRepoId() != null
                    ? repoNames.getOrDefault(scan.getRepoId(), "Repository #" + scan.getRepoId())
                    : containerNames.getOrDefault(scan.getContainerId(), "Container #" + scan.getContainerId());

            if (ScanStatus.SCANNING.wireName().equals(scan.getStatus())) {
                String agentId = scan.getClaimedBy();
                String agentName = agentId != null
                        ? agentNames.getOrDefault(agentId, agentId.equalsIgnoreCase("worker") || agentId.equalsIgnoreCase("built-in") ? "Built-in Worker" : "Agent " + agentId)
                        : "Unknown Worker";
                if (agentId != null) {
                    busyAgentIds.add(agentId);
                }
                long durationSec = scan.getClaimedAt() != null
                        ? Math.max(0, Duration.between(scan.getClaimedAt(), asOf).toSeconds())
                        : 0;

                runningItems.add(new RunningScanItem(
                        scan.getId(),
                        targetType,
                        targetId,
                        targetName,
                        scan.getBranch(),
                        agentId,
                        agentName,
                        scan.getClaimedAt() != null ? scan.getClaimedAt() : scan.getCreatedAt(),
                        durationSec,
                        scan.getRequiredAgentLabel()));
            } else if (ScanStatus.PENDING.wireName().equals(scan.getStatus())) {
                boolean isRoutable = scan.getRequiredAgentLabel() == null
                        || scan.getRequiredAgentLabel().isBlank()
                        || activeAgentLabels.contains(scan.getRequiredAgentLabel());

                long waitSec = scan.getCreatedAt() != null
                        ? Math.max(0, Duration.between(scan.getCreatedAt(), asOf).toSeconds())
                        : 0;

                pendingItems.add(new PendingScanItem(
                        scan.getId(),
                        targetType,
                        targetId,
                        targetName,
                        scan.getBranch(),
                        scan.getRequiredAgentLabel(),
                        scan.getCreatedAt(),
                        waitSec,
                        isRoutable,
                        pendingPos++));
            }
        }

        int busyCount = 0;
        for (AgentEntity a : allAgents) {
            if (busyAgentIds.contains(a.getId().toString()) && isOnline(a, asOf)) {
                busyCount++;
            }
        }
        int idleCount = Math.max(0, onlineCount - busyCount);

        long completed24h = scans.countByStatusAndCreatedAtAfter(ScanStatus.COMPLETED.wireName(), last24h);
        Double avgDurationMs = scans.findAvgDurationMsByStatusAndCreatedAtAfter(ScanStatus.COMPLETED.wireName(), last24h);
        long avgDurationSec = avgDurationMs != null ? Math.round(avgDurationMs / 1000.0) : 0;

        QueueStats stats = new QueueStats(
                allAgents.size(),
                onlineCount,
                busyCount,
                idleCount,
                runningItems.size(),
                pendingItems.size(),
                completed24h,
                avgDurationSec);

        return new AgentActivitySummary(runningItems, pendingItems, stats);
    }

    @GetMapping
    public List<Summary> list() {
        Instant asOf = clock.instant();
        Map<String, Long> running = runningByAgent();

        return agents.findAllByOrderByNameAsc().stream()
                .map(agent -> new Summary(
                        agent.getId(),
                        agent.getName(),
                        agent.getDescription(),
                        agent.getKind(),
                        agent.getEnabled(),
                        agent.getCredentialsMode(),
                        agent.getLabels(),
                        agent.getSealingPublicKey() != null,
                        agent.getMaxConcurrent(),
                        agent.getHostname(),
                        agent.getPlatform(),
                        agent.getVersion(),
                        agent.getContractVersion(),
                        agent.getLastSeenAt(),
                        isOnline(agent, asOf),
                        running.getOrDefault(agent.getId().toString(), 0L)))
                .toList();
    }

    /**
     * Declares an agent <b>and issues its key</b>, returned once.
     *
     * <p>Both together because an agent with no key can do nothing: separating them would leave
     * an inert row the operator would believe was working.
     */
    @PostMapping
    public DeclaredAgent create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        String name = body.name() == null ? "" : body.name().trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("The agent's name is required.");
        }

        CredentialsMode mode = body.credentialsMode() == null || body.credentialsMode().isBlank()
                ? CredentialsMode.LOCAL
                : CredentialsMode.byWireName(body.credentialsMode().trim())
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Unknown credentials mode: \"" + body.credentialsMode() + "\"."));

        ApiKeys.IssuedKey issued = ApiKeys.generate();
        Instant at = clock.instant();

        // The key and the agent commit together — an agent pointing at a key that was rolled
        // back is a row that can never authenticate — but the audit entry is written outside,
        // because it uses REQUIRES_NEW and a nested connection deadlocks against its own parent
        // on SQLite, where the lock is the file.
        AgentEntity saved = transactions.execute(status -> {
        ApiKeyEntity key = new ApiKeyEntity();
        key.setName("Agent " + name);
        key.setKeyHash(PasswordHasher.hash(issued.fullKey()));
        key.setPrefix(issued.prefix());
        // The only scope: an agent has no business reading the backlog or exporting anything.
        key.setScopes(ApiKeyScope.AGENT.wireName());
        key.setCreatedAt(at);
        // Saved before the agent, because the agent points at it: the identifier is generated
        // by the insert, so reading it any earlier reads null.
        ApiKeyEntity savedKey = keys.save(key);

        AgentEntity agent = new AgentEntity();
        agent.setName(name);
        agent.setDescription(text(body.description()));
        agent.setKind(AgentKind.REMOTE.wireName());
        agent.setCredentialsMode(mode.wireName());
        // Normalized on save, like the requirement a target carries: the two are compared, and
        // two divergent normalizations would leave a scan waiting for an agent that is present.
        agent.setLabels(joinedLabels(body.labels()));
        agent.setEnabled(true);
        agent.setMaxConcurrent(body.maxConcurrent() == null ? 1 : body.maxConcurrent());
        agent.setApiKeyId(savedKey.getId());
        agent.setCreatedAt(at);

        return agents.save(agent);
        });

        record(principal, request, saved.getId(), "Agent declared: " + name + " (" + mode.wireName() + ")");
        return new DeclaredAgent(saved.getId(), saved.getName(), issued.fullKey());
    }

    /** Enables or disables. A disabled agent claims nothing, without losing its history. */
    @PatchMapping("/{id}")
    public Map<String, Object> update(
            @PathVariable UUID id,
            @RequestBody UpdateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        AgentEntity agent = agents.findById(id).orElseThrow(() -> new NoSuchElementException("Agent not found."));

        boolean enabled = body.enabled() == null ? agent.getEnabled() : body.enabled();
        String labels = body.labels() == null ? agent.getLabels() : joinedLabels(body.labels());
        Integer maxConcurrent = body.maxConcurrent() == null ? agent.getMaxConcurrent() : body.maxConcurrent();

        if (!java.util.Objects.equals(labels, agent.getLabels())) {
            // **Recorded, because it is an authorization decision.** Widening an agent's labels
            // opens targets it had no access to — the same class of change as a role, and by the
            // same quiet gesture.
            record(principal, request, id, "Agent " + agent.getName() + " labels: "
                    + (labels == null ? "none" : labels) + " (previously "
                    + (agent.getLabels() == null ? "none" : agent.getLabels()) + ")");
        }
        if (enabled != agent.getEnabled()) {
            record(principal, request, id, "Agent " + agent.getName() + (enabled ? " re-enabled" : " disabled"));
        }

        agent.setEnabled(enabled);
        agent.setLabels(labels);
        agent.setMaxConcurrent(maxConcurrent);
        agents.save(agent);

        Map<String, Object> answer = new HashMap<>();
        answer.put("id", id);
        answer.put("enabled", enabled);
        answer.put("labels", labels);
        return answer;
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        AgentEntity agent = agents.findById(id).orElseThrow(() -> new NoSuchElementException("Agent not found."));

        long running = scans.countByStatusAndClaimedBy(ScanStatus.SCANNING.wireName(), id.toString());
        if (running > 0) {
            // Deleting now would leave those scans ownerless until their lease lapses, and the
            // operator would see them "running" without knowing nobody is running them.
            throw new IllegalArgumentException(
                    "This agent is running " + running + " scan(s). Disable it and wait for it to finish.");
        }

        transactions.executeWithoutResult(status -> {
            agents.deleteById(id);
        // The key goes with it: keeping it would leave an open door to the protocol with no
        // agent behind it.
            if (agent.getApiKeyId() != null) {
                keys.deleteById(agent.getApiKeyId());
            }
        });
        record(principal, request, id, "Agent deleted: " + agent.getName());
    }

    /**
     * The scans <b>nobody</b> can take, grouped by the label they require.
     *
     * <p><b>Without this screen the wait is silent.</b> A target labelled {@code customer} when
     * no enabled agent carries that label queues its scans, where they stay for ever: the
     * repositories page says "waiting", which is true and useless, and nothing names the cause.
     *
     * <p>Computed on demand rather than kept up to date: agents come and go, and a memoized
     * value would be wrong the moment one is enabled.
     */
    @GetMapping("/non-routables")
    public List<UnroutableLabel> unroutable() {
        Set<String> served = new HashSet<>();
        agents.findByEnabledTrue().forEach(agent -> served.addAll(AgentLabels.parse(agent.getLabels())));
        // The built-in worker is not a row in the table: its labels come from configuration, and
        // forgetting them here would report as blocked what is in fact running.
        served.addAll(AgentLabels.parse(worker.labels()));

        List<UnroutableLabel> unroutable = new ArrayList<>();
        for (Object[] row : scans.countPendingByRequiredLabel(ScanStatus.PENDING.wireName())) {
            String label = (String) row[0];
            if (!served.contains(label)) {
                unroutable.add(new UnroutableLabel(label, ((Number) row[1]).longValue()));
            }
        }
        return unroutable;
    }

    private Map<String, Long> runningByAgent() {
        Map<String, Long> running = new HashMap<>();
        for (Object[] row : scans.countRunningByClaimant(ScanStatus.SCANNING.wireName())) {
            running.put((String) row[0], ((Number) row[1]).longValue());
        }
        return running;
    }

    private boolean isOnline(AgentEntity agent, Instant asOf) {
        return agent.getLastSeenAt() != null
                && Duration.between(agent.getLastSeenAt(), asOf).compareTo(ONLINE_TTL) < 0;
    }

    private void record(ZanshinPrincipal principal, HttpServletRequest request, UUID id, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_UPDATED,
                id.toString(),
                description,
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }

    private static String joinedLabels(String raw) {
        List<String> labels = AgentLabels.parse(raw);
        return labels.isEmpty() ? null : String.join(",", labels);
    }

    private static String text(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
