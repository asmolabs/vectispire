package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Declaring, changing and removing agents, and reading what the queue looks like to them.
 *
 * <p><b>Boundaries are opened with a {@link TransactionTemplate}, not {@code @Transactional}.</b>
 * Declaring and deleting an agent each write two rows that must commit together, and each is
 * then audited — outside that transaction, because the audit entry uses {@code REQUIRES_NEW} and
 * a nested connection deadlocks against its own parent on SQLite, where the lock is the file. An
 * annotated method would have to either hold the audit inside its boundary or be split across
 * two beans to escape the proxy; the template states the boundary where it is.
 */
@Service
public class AgentAdministrationService {

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

    public AgentAdministrationService(
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
     * @param online seen recently, not "enabled" — see {@link #isOnline}
     * @param runningScans the scans this agent holds a lease on right now
     */
    public record AgentView(AgentEntity agent, boolean online, long runningScans) {}

    public record Declaration(
            String name, String description, String credentialsMode, String labels, Integer maxConcurrent) {}

    /** @param secret the only occurrence of the plaintext key */
    public record Declared(AgentEntity agent, String secret) {}

    /** Each field null when the caller left it as it was. */
    public record Change(Boolean enabled, String labels, Integer maxConcurrent) {}

    public record Changed(UUID id, boolean enabled, String labels) {}

    /** @param privateKey present only when the pair was generated here */
    public record PinnedKey(UUID id, boolean signsResults, String privateKey) {}

    public record Unroutable(String label, long queued) {}

    public record RunningScan(
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

    public record PendingScan(
            Long scanId,
            String targetType,
            Long targetId,
            String targetName,
            String branch,
            String requiredLabel,
            Instant queuedAt,
            long waitDurationSeconds,
            boolean routable,
            int positionInQueue) {}

    public record QueueFigures(
            int totalAgents,
            int onlineAgents,
            int busyAgents,
            int idleAgents,
            long runningScansCount,
            long pendingScansCount,
            long scansCompleted24h,
            long avgScanDurationSeconds) {}

    public record Activity(List<RunningScan> running, List<PendingScan> pending, QueueFigures figures) {}

    public Activity activity() {
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
            String name = r.getName() != null && !r.getName().isBlank() ? r.getName() : RepositoryUrl.redact(r.getUrl());
            repoNames.put(r.getId(), name != null ? name : "Repo #" + r.getId());
        });

        Map<Long, String> containerNames = new HashMap<>();
        containers.findAll().forEach(c -> {
            String name = c.getImageName() + (c.getTag() != null && !c.getTag().isBlank() ? ":" + c.getTag() : "");
            containerNames.put(c.getId(), name);
        });

        List<ScanEntity> activeScans = scans.findByStatusInOrderByCreatedAtAsc(
                List.of(ScanStatus.SCANNING.wireName(), ScanStatus.PENDING.wireName()));

        List<RunningScan> runningItems = new ArrayList<>();
        List<PendingScan> pendingItems = new ArrayList<>();
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

                runningItems.add(new RunningScan(
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

                pendingItems.add(new PendingScan(
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

        QueueFigures figures = new QueueFigures(
                allAgents.size(),
                onlineCount,
                busyCount,
                idleCount,
                runningItems.size(),
                pendingItems.size(),
                completed24h,
                avgDurationSec);

        return new Activity(runningItems, pendingItems, figures);
    }

    public List<AgentView> list() {
        Instant asOf = clock.instant();
        Map<String, Long> running = runningByAgent();
        return agents.findAllByOrderByNameAsc().stream()
                .map(agent -> new AgentView(
                        agent, isOnline(agent, asOf), running.getOrDefault(agent.getId().toString(), 0L)))
                .toList();
    }

    /**
     * Declares an agent <b>and issues its key</b>, returned once.
     *
     * <p>Both together because an agent with no key can do nothing: separating them would leave
     * an inert row the operator would believe was working.
     */
    public Declared declare(Declaration declaration, RequestActor actor) {
        String name = declaration.name() == null ? "" : declaration.name().trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("The agent's name is required.");
        }

        CredentialsMode mode = declaration.credentialsMode() == null || declaration.credentialsMode().isBlank()
                ? CredentialsMode.LOCAL
                : CredentialsMode.byWireName(declaration.credentialsMode().trim())
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Unknown credentials mode: \"" + declaration.credentialsMode() + "\"."));

        ApiKeys.IssuedKey issued = ApiKeys.generate();
        Instant at = clock.instant();

        // The key and the agent commit together — an agent pointing at a key that was rolled
        // back is a row that can never authenticate — but the audit entry is written outside,
        // for the reason given on the class.
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
            agent.setDescription(text(declaration.description()));
            agent.setKind(AgentKind.REMOTE.wireName());
            agent.setCredentialsMode(mode.wireName());
            // Normalized on save, like the requirement a target carries: the two are compared, and
            // two divergent normalizations would leave a scan waiting for an agent that is present.
            agent.setLabels(joinedLabels(declaration.labels()));
            agent.setEnabled(true);
            agent.setMaxConcurrent(declaration.maxConcurrent() == null ? 1 : declaration.maxConcurrent());
            agent.setApiKeyId(savedKey.getId());
            agent.setCreatedAt(at);

            return agents.save(agent);
        });

        record(actor, saved.getId(), "Agent declared: " + name + " (" + mode.wireName() + ")");
        return new Declared(saved, issued.fullKey());
    }

    /** Enables or disables. A disabled agent claims nothing, without losing its history. */
    public Changed change(UUID id, Change change, RequestActor actor) {
        AgentEntity agent = agents.findById(id).orElseThrow(() -> new NoSuchElementException("Agent not found."));

        boolean enabled = change.enabled() == null ? agent.getEnabled() : change.enabled();
        String labels = change.labels() == null ? agent.getLabels() : joinedLabels(change.labels());
        Integer maxConcurrent = change.maxConcurrent() == null ? agent.getMaxConcurrent() : change.maxConcurrent();

        if (!Objects.equals(labels, agent.getLabels())) {
            // **Recorded, because it is an authorization decision.** Widening an agent's labels
            // opens targets it had no access to — the same class of change as a role, and by the
            // same quiet gesture.
            record(actor, id, "Agent " + agent.getName() + " labels: "
                    + (labels == null ? "none" : labels) + " (previously "
                    + (agent.getLabels() == null ? "none" : agent.getLabels()) + ")");
        }
        if (enabled != agent.getEnabled()) {
            record(actor, id, "Agent " + agent.getName() + (enabled ? " re-enabled" : " disabled"));
        }

        agent.setEnabled(enabled);
        agent.setLabels(labels);
        agent.setMaxConcurrent(maxConcurrent);
        agents.save(agent);

        return new Changed(id, enabled, labels);
    }

    /**
     * Pins the key an agent's results must be signed with — or removes it.
     *
     * <p><b>The signing key arrives here, over an administrator's session, and never over the
     * agent protocol</b>: a key the agent announced would prove nothing its API key had not
     * already proved. See {@link ResultAttestation}.
     *
     * <p>Removing a pinned key takes the agent back to being trusted on its bearer token alone.
     * Audited as loudly as pinning one, because it is the half somebody would do quietly.
     *
     * @param publicKey base64 Ed25519, {@code "generate"} to have a pair made here, or null/blank
     *     to stop requiring signed results
     */
    public PinnedKey pinSigningKey(UUID id, String publicKey, RequestActor actor) {
        AgentEntity agent = agents.findById(id).orElseThrow(() -> new NoSuchElementException("Agent not found."));
        String supplied = publicKey == null ? "" : publicKey.trim();

        if (supplied.isEmpty()) {
            agent.setSigningPublicKey(null);
            agents.save(agent);
            recordSigningKey(actor, id,
                    "Result-signing key removed for agent " + agent.getName()
                            + ": its results are accepted on its API key alone.");
            return new PinnedKey(id, false, null);
        }

        // **Generated only when asked for by name.** A malformed key would otherwise be silently
        // replaced by a working one nobody's agent holds, and every result would be refused with
        // a message pointing at the agent.
        if ("generate".equals(supplied)) {
            ResultAttestation.KeyPair pair = ResultAttestation.generate();
            agent.setSigningPublicKey(pair.publicKey());
            agents.save(agent);
            recordSigningKey(actor, id,
                    "Result-signing key generated and pinned for agent " + agent.getName() + ".");
            return new PinnedKey(id, true, pair.privateKey());
        }

        if (!ResultAttestation.isUsablePublicKey(supplied)) {
            // Refused on the way in rather than at the first result: the failure would otherwise
            // surface on the agent, hours later, as a scan that cannot be handed back.
            throw new IllegalArgumentException(
                    "That is not an Ed25519 public key: 32 bytes of base64 are expected. Send \"generate\" "
                            + "to have one made here instead.");
        }

        agent.setSigningPublicKey(supplied);
        agents.save(agent);
        recordSigningKey(actor, id,
                "Result-signing key pinned for agent " + agent.getName() + ".");
        return new PinnedKey(id, true, null);
    }

    public void remove(UUID id, RequestActor actor) {
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
        record(actor, id, "Agent deleted: " + agent.getName());
    }

    /**
     * The scans <b>nobody</b> can take, grouped by the label they require.
     *
     * <p>Computed on demand rather than kept up to date: agents come and go, and a memoized
     * value would be wrong the moment one is enabled.
     */
    public List<Unroutable> unroutable() {
        Set<String> served = new HashSet<>();
        agents.findByEnabledTrue().forEach(agent -> served.addAll(AgentLabels.parse(agent.getLabels())));
        // The built-in worker is not a row in the table: its labels come from configuration, and
        // forgetting them here would report as blocked what is in fact running.
        served.addAll(AgentLabels.parse(worker.labels()));

        List<Unroutable> unroutable = new ArrayList<>();
        for (Object[] row : scans.countPendingByRequiredLabel(ScanStatus.PENDING.wireName())) {
            String label = (String) row[0];
            if (!served.contains(label)) {
                unroutable.add(new Unroutable(label, ((Number) row[1]).longValue()));
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

    /**
     * Seen recently, not "enabled". An enabled agent that has been silent for an hour is the case
     * that matters: the queue fills, nobody drains it, and nothing else on the screen would say so.
     */
    private boolean isOnline(AgentEntity agent, Instant asOf) {
        return agent.getLastSeenAt() != null
                && Duration.between(agent.getLastSeenAt(), asOf).compareTo(ONLINE_TTL) < 0;
    }

    private void recordSigningKey(RequestActor actor, UUID id, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_SIGNING_KEY_PINNED,
                id.toString(),
                description,
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));
    }

    private void record(RequestActor actor, UUID id, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_UPDATED,
                id.toString(),
                description,
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));
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
