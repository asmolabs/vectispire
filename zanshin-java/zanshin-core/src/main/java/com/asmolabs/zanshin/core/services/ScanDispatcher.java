package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.agents.AgentLabels;
import com.asmolabs.zanshin.common.domain.agents.CredentialsMode;
import com.asmolabs.zanshin.common.domain.crypto.SealedEnvelope;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.common.domain.targets.ImageReference;
import com.asmolabs.zanshin.common.scanning.ScanArtifacts;
import com.asmolabs.zanshin.common.scanning.ScanRunner;
import com.asmolabs.zanshin.common.scanning.ScanTask;
import com.asmolabs.zanshin.core.persistence.AgentEntity;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.persistence.SshKeyEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.ScanQueue;
import com.asmolabs.zanshin.core.repositories.SshKeys;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The dispatcher: it claims scans, has them executed, ingests their results, and gives leases
 * back.
 *
 * <p><b>Each scan gets its own transaction</b>, rather than one transaction for the whole
 * round: a scan that fails must not roll back the ingestion of the one that succeeded a moment
 * earlier, and a lease has to be returned without waiting for the others.
 *
 * <p><b>Claiming and executing are separate.</b> Claiming is short and transactional; execution
 * lasts minutes and must not hold a transaction open — it would block PostgreSQL's vacuum and
 * turn any slow scanner into a database incident.
 */
@Service
public class ScanDispatcher {

    private static final Logger log = LoggerFactory.getLogger(ScanDispatcher.class);

    /** Everything a scan of an image runs. A registry image has no tree to grep. */
    private static final Set<ScanTask.Step> IMAGE_STEPS = EnumSet.of(ScanTask.Step.DEPENDENCIES);

    private final ScanQueue queue;
    private final GitRepositories repositories;
    private final Containers containers;
    private final SshKeys sshKeys;
    private final ScanIngestor ingestor;
    private final EncryptionService encryption;
    private final SettingsService settings;
    private final RuleSetService ruleSets;
    private final SealedEnvelope envelopes;
    private final ScanningProperties properties;

    /**
     * Absent on a control plane that scans nothing itself.
     *
     * <p>A legitimate deployment: the API and the queue run here, every executor is remote. With
     * no runner, {@link #dispatch} claims nothing rather than claiming and failing — a claim it
     * cannot honour would burn one of the scan's attempts per round and fail it for good in
     * three.
     */
    private final Optional<ScanRunner> runner;

    /**
     * The transaction boundary, opened explicitly rather than by an annotation.
     *
     * <p>{@code @Transactional} on a private or self-called method does nothing at all: the
     * proxy is bypassed, the annotation reads as a guarantee, and the write runs unprotected.
     * The two boundaries here — one per scan's result — are called from inside this class, so
     * they are opened where they are meant, in code that cannot silently stop working.
     */
    private final TransactionTemplate transactions;

    public ScanDispatcher(
            ScanQueue queue,
            GitRepositories repositories,
            Containers containers,
            SshKeys sshKeys,
            ScanIngestor ingestor,
            EncryptionService encryption,
            SettingsService settings,
            RuleSetService ruleSets,
            SealedEnvelope envelopes,
            ScanningProperties properties,
            Optional<ScanRunner> runner,
            TransactionTemplate transactions) {
        this.queue = queue;
        this.repositories = repositories;
        this.containers = containers;
        this.sshKeys = sshKeys;
        this.ingestor = ingestor;
        this.encryption = encryption;
        this.settings = settings;
        this.ruleSets = ruleSets;
        this.envelopes = envelopes;
        this.properties = properties;
        this.runner = runner;
        this.transactions = transactions;
    }

    /** @param claimed how many scans this round took, of which {@code completed + failed} ran */
    public record Dispatched(int claimed, int completed, int failed) {

        static final Dispatched NOTHING = new Dispatched(0, 0, 0);
    }

    /** A task and the scan it will have to report against. */
    public record AgentTask(long scanId, ScanTask task) {}

    /**
     * One dispatch round: reclaims lost leases, then claims and executes.
     *
     * <p>{@code worker} identifies the claimant. It ends up in {@code claimedBy} and is what
     * ownership is checked against: without it, a worker whose lease expired would overwrite its
     * successor's work by handing in stale results.
     */
    public Dispatched dispatch(String worker, int maxConcurrent, List<String> agentLabels) {
        reclaimLostLeases();

        if (runner.isEmpty()) {
            return Dispatched.NOTHING;
        }

        int room = com.asmolabs.zanshin.common.domain.scans.ScanQueue.capacity(
                maxConcurrent, (int) queue.countRunning());
        if (room == 0) {
            return Dispatched.NOTHING;
        }

        List<ScanEntity> claimed = queue.claim(room, worker, agentLabels);

        int completed = 0;
        int failed = 0;
        for (ScanEntity scan : claimed) {
            // Sequential, not parallel: how much fits was already decided by the number claimed,
            // and starting five scans at once on a machine that supports one makes all five time
            // out rather than one succeed.
            if (execute(scan, worker)) {
                completed++;
            } else {
                failed++;
            }
        }
        return new Dispatched(claimed.size(), completed, failed);
    }

    /**
     * Hands one task to a remote agent, or nothing when the queue has none for it.
     *
     * <p><b>Single-shot, unlike the NestJS version</b>, which slept in a loop until its deadline.
     * The waiting belongs to the API layer, where an asynchronous request can hold the
     * connection without holding a thread — a sleeping loop here occupies a servlet thread per
     * idle agent, and a fleet of thirty idle agents was enough to starve the pool that serves
     * the interface.
     *
     * <p><b>The deployment key only leaves if it is protected.</b> An agent in {@link
     * CredentialsMode#DELEGATED} receives the repository's private key; sending it in the clear
     * hands it to whoever is listening. The scan is put back in the queue rather than entrusted.
     */
    public Optional<AgentTask> claimForAgent(AgentEntity agent, boolean secureTransport) {
        List<ScanEntity> claimed = queue.claim(1, agent.getId().toString(), AgentLabels.parse(agent.getLabels()));
        if (claimed.isEmpty()) {
            return Optional.empty();
        }

        ScanEntity scan = claimed.getFirst();
        try {
            // **The agent's mode decides; the transport only confirms.** An agent in `local` mode
            // never has a key to receive, so the question of an encrypted link does not arise
            // for it at all.
            ScanTask task = buildTask(scan, credentialsMode(agent).deliversCredentials());

            String privateKey = privateKeyOf(task);
            if (privateKey != null) {
                boolean sealed = SealedEnvelope.isUsablePublicKey(agent.getSealingPublicKey());
                if (sealed) {
                    task = withPrivateKey(task, envelopes.seal(agent.getSealingPublicKey(), privateKey));
                } else if (!secureTransport) {
                    // Put back in the queue *before* refusing: otherwise the scan stays claimed by
                    // an agent that received nothing, until the lease lapses.
                    queue.requeue(scan.getId());
                    throw new InsecureCredentialTransportException();
                }
                // An older agent announces no sealing key and therefore falls back on the
                // encrypted-transport requirement, unchanged.
            }

            return Optional.of(new AgentTask(scan.getId(), task));
        } catch (InsecureCredentialTransportException refused) {
            throw refused;
        } catch (RuntimeException error) {
            queue.fail(scan.getId(), String.valueOf(error.getMessage()));
            return Optional.empty();
        }
    }

    /** Extends the lease of a scan entrusted to this agent. */
    public boolean renewAgentLease(long scanId, AgentEntity agent) {
        return queue.renewLease(scanId, agent.getId().toString());
    }

    /**
     * Accepts the result of a scan executed elsewhere.
     *
     * <p>False when the lease was taken over in the meantime: the results are discarded rather
     * than written, so the successor's work is not overwritten.
     */
    public boolean acceptAgentResult(long scanId, AgentEntity agent, ScanArtifacts artifacts) {
        return record(scanId, agent.getId().toString(), artifacts);
    }

    private void reclaimLostLeases() {
        ScanQueue.Reclaimed reclaimed = queue.reclaimLapsedLeases();
        if (!reclaimed.requeued().isEmpty()) {
            log.warn("{} abandoned scan(s) put back in the queue.", reclaimed.requeued().size());
        }
        if (!reclaimed.failed().isEmpty()) {
            log.error("{} scan(s) failed for good after too many takeovers.", reclaimed.failed().size());
        }
    }

    /** True when the scan finished normally. */
    private boolean execute(ScanEntity scan, String worker) {
        ScanArtifacts artifacts;
        try {
            // The built-in worker runs inside the control plane and always receives the key.
            ScanTask task = buildTask(scan, true);
            // **Outside a transaction, deliberately.** Execution lasts minutes; holding one open
            // for that long blocks PostgreSQL's vacuum.
            artifacts = runner.orElseThrow().run(task);
        } catch (RuntimeException error) {
            queue.fail(scan.getId(), String.valueOf(error.getMessage()));
            return false;
        }

        try {
            if (!record(scan.getId(), worker, artifacts)) {
                log.warn("Scan {} was taken over by another worker while it ran — results discarded.", scan.getId());
            }
            return true;
        } catch (RuntimeException error) {
            queue.fail(scan.getId(), String.valueOf(error.getMessage()));
            return false;
        }
    }

    /**
     * Writes a finished scan's results, if this worker still owns it.
     *
     * <p>The ownership check is <b>inside the writing transaction</b>: between the end of
     * execution and now, another worker may have taken the scan over, and writing here would
     * overwrite its work with stale results.
     */
    private boolean record(long scanId, String worker, ScanArtifacts artifacts) {
        return Boolean.TRUE.equals(transactions.execute(status -> write(scanId, worker, artifacts)));
    }

    private boolean write(long scanId, String worker, ScanArtifacts artifacts) {
        if (!queue.stillOwned(scanId, worker)) {
            return false;
        }

        ScanEntity scan = queue.byId(scanId).orElseThrow();
        IssueSyncService.SyncResult result = ingestor.ingest(scan, artifacts);

        scan.setStatus(com.asmolabs.zanshin.common.domain.scans.ScanStatus.COMPLETED.wireName());
        scan.setFindingsCount(result.created() + result.reopened() + result.stillOpen());
        scan.setNewIssuesCount(result.created());
        scan.setResolvedIssuesCount(result.resolved());
        scan.setDurationMs(artifacts.duration().toMillis());
        artifacts.sbom().ifPresent(sbom -> scan.setSbom(sbom.toString()));
        // Step failures are recorded even on a successful scan: without them, an operator would
        // not know that one scanner looked at nothing.
        scan.setError(failureSummary(artifacts));
        scan.setClaimedBy(null);
        scan.setClaimedAt(null);
        scan.setLeaseExpiresAt(null);
        queue.save(scan);
        return true;
    }

    private static String failureSummary(ScanArtifacts artifacts) {
        if (artifacts.failures().isEmpty()) {
            return null;
        }
        String joined = artifacts.failures().stream()
                .map(failure -> failure.step() + ": " + failure.reason())
                .reduce((left, right) -> left + " | " + right)
                .orElse("");
        return joined.length() <= 2_000 ? joined : joined.substring(0, 2_000);
    }

    /**
     * Prepares the task: the private key is decrypted here, and <b>only</b> here.
     *
     * <p>The runner receives it in the clear because it has to hand it to git, but it knows
     * neither the database nor the encryption key — which is what lets a remote agent run the
     * same code without ever coming near another repository's secret.
     *
     * <p>{@code deliverCredentials} is an <b>authorization decision</b>, not a convenience. It
     * is false for an agent in {@code local} mode, and the key is then neither read nor
     * decrypted: one does not decrypt a secret one will not send.
     */
    private ScanTask buildTask(ScanEntity scan, boolean deliverCredentials) {
        if (scan.getRepoId() == null) {
            return buildImageTask(scan);
        }

        RepositoryEntity repository = repositories
                .findById(scan.getRepoId())
                .orElseThrow(() -> new IllegalStateException("Repository " + scan.getRepoId() + " no longer exists."));

        String privateKey = null;
        if (repository.getSshKeyId() != null && deliverCredentials) {
            SshKeyEntity key = sshKeys
                    .findById(repository.getSshKeyId())
                    .orElseThrow(() -> new IllegalStateException(
                            "The SSH key of repository " + repository.getUrl() + " has been deleted."));
            SecretCipher.Decrypted secret =
                    encryption.inspect(key.getPrivateKey(), SecretCipher.privateKeyContext(key.getId().toString()));
            if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
                // Said explicitly: without this, the failure would look like a refusal from the
                // git server, and the operator would go looking at the provider.
                throw new IllegalStateException(
                        "The SSH key \"" + key.getName() + "\" cannot be decrypted by any configured encryption key.");
            }
            privateKey = secret.plainText();
        }

        String branch = scan.getBranch() == null || scan.getBranch().isBlank()
                ? repository.getBranch()
                : scan.getBranch();
        String subPath = repository.getSubPath() == null ? "" : repository.getSubPath();

        Set<ScanTask.Step> steps = EnumSet.of(ScanTask.Step.DEPENDENCIES, ScanTask.Step.SECRETS, ScanTask.Step.IAC);
        // **Read here and put on the task**, never read by the worker: a remote agent has no
        // database. It was hard-coded to false in the NestJS tree, which made the whole SAST
        // chain — scanner, rules, ingestion, quality screen — unreachable without a single test
        // noticing.
        if (settings.isEnabled(Setting.SAST_ENABLED)) {
            steps.add(ScanTask.Step.SAST);
        }

        return new ScanTask(
                new ScanTask.Target.Repository(repository.getUrl(), branch, subPath, privateKey),
                // **Set by the control plane, never read by the executor.** That is what makes
                // every executor identical: an agent asking for "the active set" itself would
                // scan with whatever it found at the moment it asked, and two agents could
                // diverge on the same target.
                ruleSets.active().map(set -> set.getContentHash()).orElse(null),
                steps);
    }

    /**
     * The task of an image scan.
     *
     * <p><b>No key is ever sent</b>, whatever the agent's mode: an image is pulled from a
     * registry, not from a git repository, and registry credentials belong to the Docker
     * configuration of the machine that scans. That is what makes an image scan distributable
     * without the encrypted-link precaution a deployment key demands.
     */
    private ScanTask buildImageTask(ScanEntity scan) {
        if (scan.getContainerId() == null) {
            throw new IllegalStateException("Scan " + scan.getId() + " names neither a repository nor a container.");
        }
        ContainerEntity container = containers
                .findById(scan.getContainerId())
                .orElseThrow(() -> new IllegalStateException("Container " + scan.getContainerId() + " no longer exists."));

        return new ScanTask(
                new ScanTask.Target.Image(
                        new ImageReference(container.getRegistry(), container.getImageName(), container.getTag()),
                        // Read from the control plane's configuration and not from the agent: it
                        // is a decision about *what we want to scan* — the image that runs in
                        // production — and not about the machine that executes it.
                        properties.imagePlatform().orElse(null)),
                null,
                IMAGE_STEPS);
    }

    private static String privateKeyOf(ScanTask task) {
        return task.target() instanceof ScanTask.Target.Repository repository ? repository.privateKey() : null;
    }

    private static ScanTask withPrivateKey(ScanTask task, String privateKey) {
        ScanTask.Target.Repository repository = (ScanTask.Target.Repository) task.target();
        return new ScanTask(
                new ScanTask.Target.Repository(
                        repository.url(), repository.branch(), repository.subPath(), privateKey),
                task.rulesHash(),
                task.steps());
    }

    /**
     * An unreadable mode reads as {@code local}.
     *
     * <p>Never as {@code delegated}: the safe reading of "I do not know what this agent is
     * allowed" is "not the deployment key".
     */
    private static CredentialsMode credentialsMode(AgentEntity agent) {
        return CredentialsMode.byWireName(agent.getCredentialsMode()).orElse(CredentialsMode.LOCAL);
    }
}
