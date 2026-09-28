package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.scans.ClassifiedFailure;
import com.asmolabs.vectispire.common.domain.scans.FailureKind;
import com.asmolabs.vectispire.common.domain.scans.FailureReason;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Next;
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
import com.asmolabs.vectispire.core.scanning.internal.PlatformMetrics;
import com.asmolabs.vectispire.core.scanning.internal.ScanQueue;
import com.asmolabs.vectispire.core.scanning.internal.ScanningProperties;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
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
    private final ScanPlugins plugins;
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
            ScanPlugins plugins,
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
        this.plugins = plugins;
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

    /**
     * A task and the scan it will have to report against.
     *
     * @param attempt which attempt of the scan this claim is, counted from one. What a failure report
     *     names, so it can only ever end the attempt it is about; an agent older than the report reads
     *     past it
     */
    public record AgentTask(long scanId, int attempt, ScanTask task) {}

    /**
     * What an agent's report that it could not run its scan did.
     *
     * @param retried back in the queue for another attempt; false when the scan failed for good
     * @param permanent failed for good because the failure was permanent, not because the attempts ran out
     * @param notBefore when the scan can be claimed again; null when it failed for good
     */
    public record AgentFailure(boolean retried, int attempt, int maxAttempts, boolean permanent, Instant notBefore) {}

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

        // **This worker's own scans, not the queue's.** `maxConcurrent` is what this host can run,
        // and it used to be compared with every scan running anywhere: a fleet of remote agents
        // holding two scans left the built-in worker idle on a machine doing nothing, and one holding
        // a hundred kept it idle until they finished. `countHeld` also leaves out a lapsed lease,
        // which the reclaim above has just handed back anyway.
        int room = com.asmolabs.vectispire.common.domain.scans.ScanQueue.capacity(
                maxConcurrent, (int) queue.countHeld(worker));
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
     * <p><b>The deployment key only leaves sealed, for a key the agent proved.</b> An agent in {@link
     * CredentialsMode#DELEGATED} receives the repository's private key or HTTPS token; without a
     * sealing key signed by its pinned key it is handed no such scan at all. Whether the link is
     * encrypted no longer enters into it: TLS that a proxy terminates protects nothing from that
     * proxy, and whether one does cannot be seen from here.
     *
     * <p><b>Such an agent does not claim a scan it could not be handed.</b> It used to: the claim
     * counted an attempt, the credential was withheld and the scan put back — once per poll, every
     * few seconds, for as long as the agent ran. A scan nothing had tried reached the executor that
     * could run it with its takeovers spent, so its first lapsed lease failed it for good, and the
     * screen counted attempts that never happened: the claim the {@link #runner} field refuses for
     * the built-in worker. The repositories carrying a credential are left out of its selection
     * instead, so the scan waits for an executor that can run it and costs nothing meanwhile.
     * Refunding the attempt on the old path would have been the smaller change and the worse one:
     * the same agent would take the same scan at every poll, give it back, and keep it from a
     * verified agent or the built-in worker — a scan that neither runs nor fails.
     *
     * <p><b>It is still told, and that is not only courtesy.</b> When the agent is left with nothing
     * but scans it was kept from, the poll answers 412 as the withheld credential did: the agent logs
     * the step that is missing, which is where its operator reads it, and an agent whose key an
     * administrator reset announces a new one on that answer. A silent 204 would say "no work" to an
     * agent kept from a queue of it.
     */
    public Optional<AgentTask> claimForAgent(AgentView agent) {
        List<String> labels = AgentLabels.parse(agent.labels());
        int limit = AgentConcurrency.effective(agent.maxConcurrent());
        // Asked only of an agent that cannot be handed a credential: every other poll — a verified
        // agent's, a local one's — costs what it cost before, and the pages the queue walks, each
        // asking which of its repositories carry a credential, are the misconfiguration's price alone.
        ScanQueue.Exclusion exclusion = sealsCredentials(agent)
                ? ScanQueue.Exclusion.NONE
                : targets::carryingCredentials;

        // **Within the agent's limit, counted by the database.** The agent stops polling at its
        // limit too, but that is courtesy: two processes sharing a key, or an older agent that
        // never read the setting, would each believe they had room. The count is the one both
        // cannot get wrong, and a lowered limit therefore applies to the next claim while the
        // scans already running finish.
        ScanQueue.AgentClaim claim = queue.claimWithin(agent.id(), limit, labels, exclusion);
        Optional<ScanEntity> claimed = claim.scan();
        if (claimed.isEmpty()) {
            // Not when the agent is full: it would have been handed nothing anyway, and the answer
            // would name a missing key as the reason for a limit.
            if (claim.kept() && queue.countHeld(agent.id().toString()) < limit) {
                throw withheld(agent);
            }
            return Optional.empty();
        }

        ScanEntity scan = claimed.get();
        ScanTask built = null;
        try {
            // **The agent's mode decides.** An agent in `local` mode never has a key to receive, so
            // the question of a sealing key does not arise for it at all.
            ScanTask task = buildTask(scan, credentialsMode(agent).deliversCredentials());
            built = task;

            String privateKey = privateKeyOf(task);
            ScanTask.Target.HttpsCredential https = httpsOf(task);
            if (privateKey != null || https != null) {
                // **Sealed for the verified key, or not sent at all** (decision 0031). The key on
                // the view is one the agent signed with its pinned key; nothing else ever reaches
                // that column. There is no clear fallback, over TLS or otherwise: a credential in
                // the clear is readable by whatever terminates TLS on the way, and the absence of a
                // key is exactly what removing the announcement would look like from here.
                String sealingKey = agent.sealingPublicKey();
                if (!SealedEnvelope.isUsablePublicKey(sealingKey)) {
                    // Reached through a race only: the selection left out every repository that
                    // carried a credential when it read them, and this one gained its key since.
                    // Put back *before* refusing, or the scan stays claimed by an agent that received
                    // nothing until the lease lapses — and with its attempt refunded, since nothing
                    // was tried. The refund is paid once, because the next selection reads the key
                    // and leaves the repository out; that is what makes it safe here and nowhere
                    // else (see `returnUndelivered`).
                    queue.requeueRefunded(scan.getId(), agent.id().toString());
                    throw withheld(agent);
                }
                // The token is sealed exactly as the key is (decision 0022); its host and user
                // name are not secrets and travel in the clear, so the agent can enforce the
                // binding before opening anything. Each is sealed on its own: the screens refuse a
                // repository with both, but a row that has both must not see one leave in the clear.
                if (privateKey != null) {
                    task = withPrivateKey(task, envelopes.seal(sealingKey, privateKey));
                }
                if (https != null) {
                    task = withHttps(task, new ScanTask.Target.HttpsCredential(
                            https.host(), https.username(), envelopes.seal(sealingKey, https.token())));
                }
                recordCredentialSent(agent, scan, "sealed for the agent's verified sealing key");
            }

            return Optional.of(new AgentTask(scan.getId(), scan.getAttempts(), task));
        } catch (CredentialWithheldException refused) {
            throw refused;
        } catch (RuntimeException error) {
            // The same rule as the agent's own report and the built-in worker's: a repository whose
            // URL the allow-list now refuses fails at once, a key store that did not answer retries.
            abandon(scan, agent.id().toString(), "for agent \"" + agent.name() + "\"", error, built);
            return Optional.empty();
        }
    }

    /**
     * Whether a scan needing a delegated credential may be claimed for this agent — the dispatcher's
     * own predicate, published so that a figure of the scans nobody can take counts with the rule the
     * claim applies, not with a copy of it.
     */
    public static boolean canBeHandedCredentials(AgentView agent) {
        return sealsCredentials(agent);
    }

    /**
     * Whether this control plane scans anything itself: without a runner the built-in worker claims
     * nothing, whatever its configuration says — see {@code runner}.
     */
    public boolean runsScansHere() {
        return runner.isPresent();
    }

    /**
     * Whether a scan needing a delegated credential may be claimed for this agent.
     *
     * <p>True for an agent that is never handed one — {@code local}, or a mode this version cannot
     * read — since the credential then stays here and the agent clones with its own. The one
     * predicate the selection and the delivery both come down to: two tests that could disagree
     * would hand an agent a scan it is then refused, or keep it from one it could have run.
     */
    private static boolean sealsCredentials(AgentView agent) {
        return !credentialsMode(agent).deliversCredentials()
                || SealedEnvelope.isUsablePublicKey(agent.sealingPublicKey());
    }

    private static CredentialWithheldException withheld(AgentView agent) {
        return new CredentialWithheldException(
                agent.signingPublicKey() == null || agent.signingPublicKey().isBlank());
    }

    /**
     * Records that a deployment key left the control plane.
     *
     * <p>The interesting question afterwards is "which machines have held this repository's key".
     * Every delivery is sealed since decision 0031; how it travelled stays in the description, which
     * is where an auditor reading an older entry — some of which say "in the clear" — looks.
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

    /**
     * An agent's word that it could not run the scan it claimed — the clone refused, the workspace
     * not made, a credential that would not open: anything before a result exists.
     *
     * <p><b>The lapse's rule, without its twenty minutes.</b> The agent used to drop the scan and say
     * nothing: the lease ran out, the reclaim requeued it with the attempt spent, and the reason stayed
     * in a log on another machine. What the report changes is when, and that the reason is on the scan
     * for the screen to show; what it does to the attempts is exactly what the lapse would have done.
     *
     * <p>Only while the scan is still this agent's, at that attempt: a report sent twice, or about an
     * attempt since superseded, changes nothing.
     *
     * <p><b>The agent's kind decides between failing and waiting</b> — see {@link ScanQueue#abandon}.
     * Without the wait a lone agent took back at its next poll the scan it had just reported, and three
     * attempts were spent in seconds.
     *
     * @param kind what the agent says of the failure; transient when its report named none
     * @param reason already scrubbed — see {@code FailureReason}
     */
    public Optional<AgentFailure> reportAgentFailure(
            long scanId, AgentView agent, int attempt, FailureKind kind, String reason) {
        Instant claimedAt = queue.byId(scanId).map(ScanEntity::getClaimedAt).orElse(null);
        String where = "on agent \"" + agent.name() + "\"";
        Optional<ScanQueue.Abandoned> abandoned =
                queue.abandon(scanId, agent.id().toString(), attempt, kind, outcome -> sentence(outcome, where, reason));
        abandoned.ifPresent(done -> {
            metrics.scanFinishedSince(claimedAt, false, true);
            logAbandoned(scanId, where, done);
        });
        return abandoned.map(done -> new AgentFailure(
                done.retried(), done.attempt(), done.maxAttempts(), done.permanent(), done.notBefore().orElse(null)));
    }

    /**
     * What a scan that could not run says of it, whichever executor it was.
     *
     * @param where where the attempt failed — {@code on agent "edge"}, {@code on the built-in worker}
     */
    static String sentence(ScanQueue.Abandoned outcome, String where, String reason) {
        String attempt = "Attempt " + outcome.attempt() + " of " + outcome.maxAttempts() + " could not run " + where;
        String next = switch (outcome.next()) {
            // To the second: the instant is read by a person, and its nanoseconds are the clock's, not the rule's.
            case Next.Retry(Instant notBefore) -> "; the scan is back in the queue, not before "
                    + notBefore.truncatedTo(java.time.temporal.ChronoUnit.SECONDS) + ": ";
            case Next.Fail(boolean permanent) when permanent -> ", and another attempt would meet the same refusal: ";
            case Next.Fail fail -> ", and it was the last: ";
        };
        return attempt + next + reason;
    }

    private static void logAbandoned(long scanId, String where, ScanQueue.Abandoned done) {
        if (done.permanent()) {
            log.warn("Scan {} failed for good {}: the failure is not one another attempt would pass.", scanId, where);
        } else if (!done.retried()) {
            log.warn("Scan {} failed for good {} after {} attempts.", scanId, where, done.attempt());
        } else {
            log.info("Scan {} could not run {} (attempt {} of {}) — back in the queue, not before {}.",
                    scanId, where, done.attempt(), done.maxAttempts(), done.notBefore().orElse(null));
        }
    }

    /**
     * Ends an attempt that failed here, by the same rule as an agent's report — the kind read off the
     * exception, the reason scrubbed of what the task carried and of what has a secret's shape.
     *
     * <p><b>Scrubbed although it never leaves the control plane.</b> It reaches the scan's row, which
     * every account that sees the target reads, and a clone's message can quote what the clone held;
     * an agent's reason is scrubbed on both sides before it lands in the same column.
     *
     * @param task what was handed to the runner, for its secrets; null when the failure came first
     */
    private void abandon(ScanEntity scan, String worker, String where, RuntimeException error, ScanTask task) {
        String raw = error.getMessage() == null ? error.toString() : error.getMessage();
        String reason = FailureReason.scrub(raw, secretsOf(task));
        FailureKind kind = FailureKind.of(error);
        queue.abandon(scan.getId(), worker, scan.getAttempts(), kind,
                        outcome -> sentence(outcome, where, reason.isEmpty() ? "no reason was given." : reason))
                .ifPresent(done -> logAbandoned(scan.getId(), where, done));
    }

    private static List<String> secretsOf(ScanTask task) {
        // Nulls included: the scrub skips them, and a list that refused one would lose the rest.
        List<String> secrets = new java.util.ArrayList<>();
        if (task != null && task.target() instanceof ScanTask.Target.Repository repository) {
            secrets.add(repository.privateKey());
            secrets.add(repository.https() == null ? null : repository.https().token());
        }
        return secrets;
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
        ScanTask task = null;
        ScheduledFuture<?> heartbeat = keepLeased(scan.getId(), worker);
        try {
            // The built-in worker runs inside the control plane and always receives the key.
            task = buildTask(scan, true);
            // **Outside a transaction, deliberately.** Execution lasts minutes; holding one open
            // for that long blocks PostgreSQL's vacuum.
            artifacts = runner.orElseThrow().run(task);
        } catch (RuntimeException error) {
            // **The agents' rule, not a rule of its own.** This used to fail the scan for good at the
            // first error, with the raw message: a network blip that cost an agent one attempt of
            // three cost the built-in worker the scan. A step that failed inside a scan that ran is
            // not this — it is in the artifacts, absent (decision 0007) — this is a scan that could
            // not run at all.
            abandon(scan, worker, "on the built-in worker", error, task);
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
            // Its results could not be written, and the write rolled back: the scan is still this
            // worker's, as an agent's is when its upload fails — which ends in a lapse, a transient
            // failure. The same here, without the twenty minutes.
            abandon(scan, worker, "on the built-in worker", error, task);
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
        // Each plugin's outcome, the not-applicable ones included — which are nobody's failure and
        // would otherwise be recorded nowhere.
        scan.setPluginSteps(PluginOutcome.write(artifacts.plugins()));
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
     * A task this control plane will not build, for a reason no later attempt changes: its target is
     * gone, its URL refused by the rules or the allow-list, its credential deleted or sealed under no
     * key configured here. Permanent, so the scan fails with the reason instead of spending its
     * attempts on it. What {@link EncryptionService} raises when a key store does not answer is not
     * one of these, and retries.
     */
    static final class TaskRefused extends IllegalStateException implements ClassifiedFailure {

        private static final long serialVersionUID = 1L;

        TaskRefused(String message) {
            super(message);
        }

        @Override
        public FailureKind failureKind() {
            return FailureKind.PERMANENT;
        }
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
                .orElseThrow(() -> new TaskRefused("Repository " + scan.getRepoId() + " no longer exists."));
        // The URL's own rules, before its host is judged: a row registered before a rule existed —
        // an address two parsers read as two different hosts, since 2026-09 — is refused before its
        // task and its credential leave for an agent, not only by the clone at the other end.
        RepositoryUrl.validate(repository.url()).ifPresent(reason -> {
            throw new TaskRefused("Repository URL refused: " + reason);
        });
        // Again here, not only when the URL was entered: a list tightened after a repository was
        // registered has to stop its scans too, and this is the one place every executor's task
        // is built — the worker's and every agent's.
        if (!allowedHosts.permits(repository.url())) {
            throw new TaskRefused(allowedHosts.refusal(RepositoryUrl.redact(repository.url())));
        }

        ScanTask.Target.HttpsCredential https = null;
        if (repository.httpsTokenId() != null && deliverCredentials) {
            CloneCredentials.StoredGitToken token = credentials
                    .gitToken(repository.httpsTokenId())
                    .orElseThrow(() -> new TaskRefused(
                            "The HTTPS token of repository " + RepositoryUrl.redact(repository.url()) + " has been deleted."));
            SecretCipher.Decrypted secret =
                    encryption.inspect(token.ciphertext(), SecretCipher.gitTokenContext(token.id().toString()));
            if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
                throw new TaskRefused(
                        "The HTTPS token \"" + token.name() + "\" cannot be decrypted by any configured encryption key.");
            }
            https = new ScanTask.Target.HttpsCredential(token.host(), token.username(), secret.plainText());
        }

        String privateKey = null;
        if (repository.sshKeyId() != null && deliverCredentials) {
            CloneCredentials.StoredSshKey key = credentials
                    .sshKey(repository.sshKeyId())
                    .orElseThrow(() -> new TaskRefused(
                            "The SSH key of repository " + RepositoryUrl.redact(repository.url()) + " has been deleted."));
            SecretCipher.Decrypted secret =
                    encryption.inspect(key.ciphertext(), SecretCipher.privateKeyContext(key.id().toString()));
            if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
                // Said explicitly: without this, the failure would look like a refusal from the
                // git server, and the operator would go looking at the provider.
                throw new TaskRefused(
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
                steps,
                // **Decided here too, by id and manifest digest**, for the rule set's reason: an
                // executor that looked the plugins up for itself would run what it found when it
                // asked. The project the repository is filed in decides which; none, none.
                plugins.forRepository(repository.id()));
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
            throw new TaskRefused("Scan " + scan.getId() + " names neither a repository nor a container.");
        }
        ContainerView container = targets
                .container(scan.getContainerId())
                .orElseThrow(() -> new TaskRefused("Container " + scan.getContainerId() + " no longer exists."));

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
        return task.withTarget(((ScanTask.Target.Repository) task.target()).withPrivateKey(privateKey));
    }

    private static ScanTask.Target.HttpsCredential httpsOf(ScanTask task) {
        return task.target() instanceof ScanTask.Target.Repository repository ? repository.https() : null;
    }

    private static ScanTask withHttps(ScanTask task, ScanTask.Target.HttpsCredential https) {
        return task.withTarget(((ScanTask.Target.Repository) task.target()).withHttps(https));
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
