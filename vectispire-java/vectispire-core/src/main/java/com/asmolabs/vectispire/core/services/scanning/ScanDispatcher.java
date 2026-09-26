package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist;
import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.CloneCredentials;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
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

    /** One daemon thread for every lease the built-in worker keeps alive — see {@link #keepLeased}. */
    private final ScheduledExecutorService leaseKeeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "vectispire-lease-keeper");
        thread.setDaemon(true);
        return thread;
    });
    private final TargetCatalog targets;
    private final CloneCredentials credentials;
    private final GitHostAllowlist allowedHosts;
    private final ScanIngestor ingestor;
    private final EncryptionService encryption;
    private final SettingsService settings;
    private final ScanRuleSets ruleSets;
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
    private final PlatformMetrics metrics;
    private final TransactionTemplate transactions;

    /**
     * The ledger for the one thing here that leaves the trust boundary.
     *
     * <p>{@code AGENT_CREDENTIAL_SENT} has existed in {@link AuditOperation} since the agent
     * protocol was written, with a javadoc describing exactly this moment — and nothing recorded
     * it. A deployment key left for another machine and the audit log said a scan had been
     * claimed.
     */
    private final AuditLogService audit;

    public ScanDispatcher(
            ScanQueue queue,
            TargetCatalog targets,
            CloneCredentials credentials,
            ScanIngestor ingestor,
            EncryptionService encryption,
            SettingsService settings,
            ScanRuleSets ruleSets,
            SealedEnvelope envelopes,
            ScanningProperties properties,
            Optional<ScanRunner> runner,
            AuditLogService audit,
            PlatformMetrics metrics,
            TransactionTemplate transactions,
            GitHostAllowlist allowedHosts) {
        this.queue = queue;
        this.targets = targets;
        this.credentials = credentials;
        this.ingestor = ingestor;
        this.encryption = encryption;
        this.settings = settings;
        this.ruleSets = ruleSets;
        this.envelopes = envelopes;
        this.properties = properties;
        this.runner = runner;
        this.audit = audit;
        this.metrics = metrics;
        this.transactions = transactions;
        this.allowedHosts = allowedHosts;
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

        int room = com.asmolabs.vectispire.common.domain.scans.ScanQueue.capacity(
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
     * Hands one task to a remote agent, or nothing when the queue has none for it or the agent
     * already runs as many scans as its {@code max_concurrent} allows.
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
    public Optional<AgentTask> claimForAgent(AgentView agent, boolean secureTransport) {
        // **Within the agent's limit, counted by the database.** The agent stops polling at its
        // limit too, but that is courtesy: two processes sharing a key, or an older agent that
        // never read the setting, would each believe they had room. The count is the one both
        // cannot get wrong, and a lowered limit therefore applies to the next claim while the
        // scans already running finish.
        Optional<ScanEntity> claimed = queue.claimWithin(
                agent.id(), AgentConcurrency.effective(agent.maxConcurrent()), AgentLabels.parse(agent.labels()));
        if (claimed.isEmpty()) {
            return Optional.empty();
        }

        ScanEntity scan = claimed.get();
        try {
            // **The agent's mode decides; the transport only confirms.** An agent in `local` mode
            // never has a key to receive, so the question of an encrypted link does not arise
            // for it at all.
            ScanTask task = buildTask(scan, credentialsMode(agent).deliversCredentials());

            String privateKey = privateKeyOf(task);
            ScanTask.Target.HttpsCredential https = httpsOf(task);
            if (privateKey != null || https != null) {
                boolean sealed = SealedEnvelope.isUsablePublicKey(agent.sealingPublicKey());
                if (sealed) {
                    // The token is sealed exactly as the key is (decision 0022); its host and user
                    // name are not secrets and travel in the clear, so the agent can enforce the
                    // binding before opening anything.
                    task = privateKey != null
                            ? withPrivateKey(task, envelopes.seal(agent.sealingPublicKey(), privateKey))
                            : withHttps(task, new ScanTask.Target.HttpsCredential(
                                    https.host(), https.username(), envelopes.seal(agent.sealingPublicKey(), https.token())));
                    recordCredentialSent(agent, scan, "sealed for the agent's announced key");
                } else if (!secureTransport) {
                    // Put back in the queue *before* refusing: otherwise the scan stays claimed by
                    // an agent that received nothing, until the lease lapses.
                    queue.requeue(scan.getId(), agent.id().toString());
                    throw new InsecureCredentialTransportException();
                }
                // An older agent announces no sealing key and therefore falls back on the
                // encrypted-transport requirement, unchanged.
                if (!sealed) {
                    recordCredentialSent(agent, scan, "in the clear over an encrypted link");
                }
            }

            return Optional.of(new AgentTask(scan.getId(), task));
        } catch (InsecureCredentialTransportException refused) {
            throw refused;
        } catch (RuntimeException error) {
            queue.fail(scan.getId(), agent.id().toString(), String.valueOf(error.getMessage()));
            return Optional.empty();
        }
    }

    /**
     * Records that a deployment key left the control plane.
     *
     * <p><b>Written whichever way it left</b>, sealed or in the clear, because the interesting
     * question afterwards is "which machines have held this repository's key", and a log that
     * only names the risky path cannot answer it. How it travelled is in the description, which is
     * where an auditor reading a specific entry looks.
     */
    private void recordCredentialSent(AgentView agent, ScanEntity scan, String how) {
        audit.record(AuditLogService.Record.of(
                AuditOperation.AGENT_CREDENTIAL_SENT,
                String.valueOf(scan.getId()),
                "Deployment key delegated to agent \"" + agent.name() + "\" for scan " + scan.getId()
                        + ", " + how + ".",
                agent.name()));
    }

    /**
     * Puts back a scan claimed for an agent that never received it.
     *
     * <p>Only while the claim is still that agent's: the release carries the owner, so a scan
     * another worker has since taken is left alone. The attempt the claim counted is not refunded —
     * a scan that keeps going undelivered should reach its limit rather than circulate for ever.
     */
    public void returnUndelivered(long scanId, AgentView agent) {
        if (queue.requeue(scanId, agent.id().toString())) {
            log.info("Scan {} was claimed for agent \"{}\" but never delivered — back in the queue.",
                    scanId, agent.name());
        }
    }

    /** Extends the lease of a scan entrusted to this agent. */
    public boolean renewAgentLease(long scanId, AgentView agent) {
        return queue.renewLease(scanId, agent.id().toString());
    }

    /**
     * Accepts the result of a scan executed elsewhere.
     *
     * <p>False when the lease was taken over in the meantime: the results are discarded rather
     * than written, so the successor's work is not overwritten.
     */
    public boolean acceptAgentResult(long scanId, AgentView agent, ScanArtifacts artifacts) {
        // Read before the write, because recording the result clears the claim. Timed from the
        // claim rather than from the submission: what an operator wants to know is how long the
        // agent held the work, which is the number that grows when an agent is struggling.
        Instant claimedAt = queue.byId(scanId).map(ScanEntity::getClaimedAt).orElse(null);
        boolean accepted = record(scanId, agent.id().toString(), artifacts);
        metrics.scanFinishedSince(claimedAt, accepted, true);
        return accepted;
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
        // **Renewed before it starts.** A round claims several scans at once and runs them one
        // after the other, all leased from the moment of the claim: the third could lapse before
        // it began, be reclaimed elsewhere, and run twice. Renewing here either restarts the
        // clock or reveals that another worker already has it.
        if (!queue.renewLease(scan.getId(), worker)) {
            log.warn("Scan {} was taken over before it started — skipped.", scan.getId());
            return false;
        }

        ScanArtifacts artifacts;
        ScheduledFuture<?> heartbeat = keepLeased(scan.getId(), worker);
        try {
            // The built-in worker runs inside the control plane and always receives the key.
            ScanTask task = buildTask(scan, true);
            // **Outside a transaction, deliberately.** Execution lasts minutes; holding one open
            // for that long blocks PostgreSQL's vacuum.
            artifacts = runner.orElseThrow().run(task);
        } catch (RuntimeException error) {
            queue.fail(scan.getId(), worker, String.valueOf(error.getMessage()));
            metrics.scanFinishedSince(scan.getClaimedAt(), false, false);
            return false;
        } finally {
            heartbeat.cancel(false);
        }

        try {
            if (!record(scan.getId(), worker, artifacts)) {
                log.warn("Scan {} was taken over by another worker while it ran — results discarded.", scan.getId());
            }
            metrics.scanFinishedSince(scan.getClaimedAt(), true, false);
            return true;
        } catch (RuntimeException error) {
            queue.fail(scan.getId(), worker, String.valueOf(error.getMessage()));
            metrics.scanFinishedSince(scan.getClaimedAt(), false, false);
            return false;
        }
    }

    /**
     * Renews the lease while the built-in worker runs a scan.
     *
     * <p><b>Only remote agents renewed until now</b>, through their own route. The built-in worker
     * held the lease it was claimed with: any scan longer than the lease was reclaimed by another
     * instance while it still ran, executed twice, and cost an attempt each time until it failed
     * as "lease exhausted" — on a target that was simply slow.
     *
     * <p>A third of the lease, so two renewals can be lost before it lapses. A failed renewal is
     * logged and the next one tried: the scan is not interrupted, and if it has been taken over
     * the write will say so.
     */
    private ScheduledFuture<?> keepLeased(long scanId, String worker) {
        long period = Math.max(1_000L, queue.lease().toMillis() / 3);
        return leaseKeeper.scheduleAtFixedRate(() -> {
            try {
                if (!queue.renewLease(scanId, worker)) {
                    log.warn("Scan {} is no longer this worker's — its results will be discarded.", scanId);
                }
            } catch (RuntimeException unavailable) {
                // Caught, or the executor would silently cancel every later renewal.
                log.warn("Lease renewal for scan {} failed: {}", scanId, unavailable.getMessage());
            }
        }, period, period, TimeUnit.MILLISECONDS);
    }

    @PreDestroy
    void stopLeaseKeeper() {
        leaseKeeper.shutdownNow();
    }

    /**
     * Writes a finished scan's results, if this worker still owns it.
     *
     * <p>The ownership check is <b>inside the writing transaction</b>: between the end of
     * execution and now, another worker may have taken the scan over, and writing here would
     * overwrite its work with stale results.
     */
    private boolean record(long scanId, String worker, ScanArtifacts artifacts) {
        // **The remote lookups first, then the transaction.** End of life asks a public catalogue,
        // and asking it inside `write` held the scan's row lock — the one that fences a concurrent
        // reclaim — for as long as the catalogue took to answer.
        Optional<ScanIngestor.Prepared> prepared = queue.byId(scanId).map(scan -> ingestor.prepare(scan, artifacts));
        if (prepared.isEmpty()) {
            return false;
        }
        return Boolean.TRUE.equals(transactions.execute(status -> write(scanId, worker, artifacts, prepared.get())));
    }

    private boolean write(long scanId, String worker, ScanArtifacts artifacts, ScanIngestor.Prepared prepared) {
        // Holds the row until this transaction commits — see `holdForWrite`.
        if (!queue.holdForWrite(scanId, worker)) {
            return false;
        }

        ScanEntity scan = queue.byId(scanId).orElseThrow();
        ScanIngestor.Reconciliation result = ingestor.ingest(scan, artifacts, prepared);

        // **A scan that observed nothing is a failure, not a completed scan.** Every step
        // absent *and* something broken means the target was never examined — the case that
        // named this was an image whose repository does not exist, where the pull fails and
        // takes every step with it. Recorded as completed, it reached the screen as a finished
        // scan with a green tag, and an operator reasonably read it as "this image is clean".
        //
        // Nothing observed with no failure either is left completed on purpose: that is a task
        // asked to run no step, which is a configuration to look at and not an error to report.
        boolean nothingExamined = artifacts.observedNothing() && !artifacts.failures().isEmpty();
        scan.setStatus(
                (nothingExamined
                                ? com.asmolabs.vectispire.common.domain.scans.ScanStatus.FAILED
                                : com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED)
                        .wireName());
        scan.setFindingsCount(result.created() + result.reopened() + result.stillOpen());
        scan.setNewIssuesCount(result.created());
        scan.setResolvedIssuesCount(result.resolved());
        // Unknown rather than a crash: an agent result that omits the duration is still a result,
        // and failing the whole write over a timing would throw away its findings.
        scan.setDurationMs(artifacts.duration() == null ? null : artifacts.duration().toMillis());
        artifacts.sbom().ifPresent(sbom -> scan.setSbom(sbom.toString()));
        // Left untouched when absent rather than blanked: a scan whose clone carried no manifest
        // says nothing about the target's ecosystem, and overwriting what a previous scan read
        // would turn "we did not find it this time" into "it does not have one".
        artifacts.project().ifPresent(project -> {
            scan.setProjectType(project.type());
            scan.setVersion(project.version());
        });
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

        RepositoryView repository = targets
                .repository(scan.getRepoId())
                .orElseThrow(() -> new IllegalStateException("Repository " + scan.getRepoId() + " no longer exists."));
        // Again here, not only when the URL was entered: a list tightened after a repository was
        // registered has to stop its scans too, and this is the one place every executor's task
        // is built — the worker's and every agent's.
        if (!allowedHosts.permits(repository.url())) {
            throw new IllegalStateException(allowedHosts.refusal(RepositoryUrl.redact(repository.url())));
        }

        ScanTask.Target.HttpsCredential https = null;
        if (repository.httpsTokenId() != null && deliverCredentials) {
            CloneCredentials.StoredGitToken token = credentials
                    .gitToken(repository.httpsTokenId())
                    .orElseThrow(() -> new IllegalStateException(
                            "The HTTPS token of repository " + RepositoryUrl.redact(repository.url()) + " has been deleted."));
            SecretCipher.Decrypted secret =
                    encryption.inspect(token.ciphertext(), SecretCipher.gitTokenContext(token.id().toString()));
            if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
                throw new IllegalStateException(
                        "The HTTPS token \"" + token.name() + "\" cannot be decrypted by any configured encryption key.");
            }
            https = new ScanTask.Target.HttpsCredential(token.host(), token.username(), secret.plainText());
        }

        String privateKey = null;
        if (repository.sshKeyId() != null && deliverCredentials) {
            CloneCredentials.StoredSshKey key = credentials
                    .sshKey(repository.sshKeyId())
                    .orElseThrow(() -> new IllegalStateException(
                            "The SSH key of repository " + RepositoryUrl.redact(repository.url()) + " has been deleted."));
            SecretCipher.Decrypted secret =
                    encryption.inspect(key.ciphertext(), SecretCipher.privateKeyContext(key.id().toString()));
            if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
                // Said explicitly: without this, the failure would look like a refusal from the
                // git server, and the operator would go looking at the provider.
                throw new IllegalStateException(
                        "The SSH key \"" + key.name() + "\" cannot be decrypted by any configured encryption key.");
            }
            privateKey = secret.plainText();
        }

        String branch = scan.getBranch() == null || scan.getBranch().isBlank()
                ? repository.branch()
                : scan.getBranch();
        String subPath = repository.subPath() == null ? "" : repository.subPath();

        Set<ScanTask.Step> steps = EnumSet.of(ScanTask.Step.DEPENDENCIES, ScanTask.Step.SECRETS, ScanTask.Step.IAC);
        // **Read here and put on the task**, never read by the worker: a remote agent has no
        // database. It was hard-coded to false in the NestJS tree, which made the whole SAST
        // chain — scanner, rules, ingestion, quality screen — unreachable without a single test
        // noticing.
        if (settings.isEnabled(Setting.SAST_ENABLED)) {
            steps.add(ScanTask.Step.SAST);
        }

        return new ScanTask(
                new ScanTask.Target.Repository(repository.url(), branch, subPath, privateKey, https),
                // **Set by the control plane, never read by the executor.** That is what makes
                // every executor identical: an agent asking for "the active set" itself would
                // scan with whatever it found at the moment it asked, and two agents could
                // diverge on the same target.
                ruleSets.activeHash().orElse(null),
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
        ContainerView container = targets
                .container(scan.getContainerId())
                .orElseThrow(() -> new IllegalStateException("Container " + scan.getContainerId() + " no longer exists."));

        return new ScanTask(
                new ScanTask.Target.Image(
                        new ImageReference(container.registry(), container.imageName(), container.tag()),
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
                        repository.url(), repository.branch(), repository.subPath(), privateKey, repository.https()),
                task.rulesHash(),
                task.steps());
    }

    private static ScanTask.Target.HttpsCredential httpsOf(ScanTask task) {
        return task.target() instanceof ScanTask.Target.Repository repository ? repository.https() : null;
    }

    private static ScanTask withHttps(ScanTask task, ScanTask.Target.HttpsCredential https) {
        ScanTask.Target.Repository repository = (ScanTask.Target.Repository) task.target();
        return new ScanTask(
                new ScanTask.Target.Repository(
                        repository.url(), repository.branch(), repository.subPath(), repository.privateKey(), https),
                task.rulesHash(),
                task.steps());
    }

    /**
     * An unreadable mode reads as {@code local}.
     *
     * <p>Never as {@code delegated}: the safe reading of "I do not know what this agent is
     * allowed" is "not the deployment key".
     */
    private static CredentialsMode credentialsMode(AgentView agent) {
        return CredentialsMode.byWireName(agent.credentialsMode()).orElse(CredentialsMode.LOCAL);
    }
}
