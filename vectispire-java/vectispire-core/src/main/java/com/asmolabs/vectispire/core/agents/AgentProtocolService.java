package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SealingKeyAttestation;
import com.asmolabs.vectispire.common.domain.scans.FailureKind;
import com.asmolabs.vectispire.common.domain.scans.FailureReason;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * What the control plane decides when a remote agent speaks: whether its announcement is
 * acceptable, whether a result it hands back is, and what a scan it could not run becomes.
 *
 * <p>The agent is already authenticated when it gets here — that is the controller's, from the
 * principal. The outcomes are closed sets rather than exceptions because each one is a distinct
 * answer the agent acts on (update yourself, give up this scan, sign your results), and the
 * status each maps to is the protocol's to state, next to the route.
 */
@Service
public class AgentProtocolService {

    private final AgentRepository agents;
    private final ScanDispatcher dispatcher;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final Clock clock;

    /**
     * How old the last sign of life may be before a poll writes a new one. Well inside the two
     * minutes after which an agent reads as offline, with a thirty-second poll in between: the
     * column is at most forty-five seconds behind an agent that is polling.
     */
    static final Duration SEEN_GRANULARITY = Duration.ofSeconds(15);

    public AgentProtocolService(
            AgentRepository agents, ScanDispatcher dispatcher, AuditLogService audit, ObjectMapper json, Clock clock) {
        this.agents = agents;
        this.dispatcher = dispatcher;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
    }

    /**
     * What a {@code hello} says. It carries no sealing key any more: the one an agent still sends
     * there, for a control plane older than decision 0031, is unsigned and read by nothing here.
     */
    public record Announcement(
            String contractVersion,
            String hostname,
            String platform,
            String version,
            String scannerEngine,
            String capabilities) {}

    public sealed interface Hello {
        /** @param announced the version the agent claimed, empty when it claimed none */
        record IncompatibleContract(String announced) implements Hello {}

        /**
         * @param maxConcurrent the limit the queue applies, not the column: a row written before
         *     the bound existed would otherwise announce a limit the claim then refuses to honour
         */
        record Accepted(int maxConcurrent) implements Hello {}
    }

    /**
     * A sealing key, signed with the agent's pinned result-signing key.
     *
     * @param generation when the agent made the pair, in epoch milliseconds; null when absent
     */
    public record SealingKeyAnnouncement(String publicKey, Long generation, String signature) {}

    /** What became of a sealing key an agent announced. */
    public sealed interface SealingKey {

        /** @param rotated false when the agent repeated the key already held */
        record Accepted(boolean rotated) implements SealingKey {}

        /** Not an X25519 key, or no positive generation: there is nothing to verify. */
        record Unreadable() implements SealingKey {}

        /** No signing key is pinned for this agent, so no sealing key can be believed. */
        record NotPinned() implements SealingKey {}

        /** The signature does not verify against the pinned key. Audited. */
        record NotVerified() implements SealingKey {}

        /** Older than the key already accepted — a clock put back, or an announcement replayed. Audited. */
        record Stale() implements SealingKey {}
    }

    public sealed interface Submission {
        record Accepted() implements Submission {}

        /** A signing key is pinned for this agent and the body does not carry its signature. */
        record NotAttested() implements Submission {}

        record Unreadable() implements Submission {}

        /** The lease was taken over while the agent worked; its results were discarded. */
        record NoLongerYours() implements Submission {}
    }

    /** What became of an agent's report that it could not run a scan. */
    public sealed interface FailureOutcome {

        /**
         * @param retried back in the queue; false when the scan failed for good
         * @param permanent failed for good because the agent said another attempt would fail the same way
         * @param retryAt when the scan can be claimed again; null when it failed for good
         */
        record Recorded(boolean retried, int attempt, int maxAttempts, boolean permanent, java.time.Instant retryAt)
                implements FailureOutcome {}

        /** A signing key is pinned for this agent and the report does not carry its signature. Audited. */
        record NotAttested() implements FailureOutcome {}

        /** Not JSON, or no attempt named: there is nothing to apply. */
        record Unreadable() implements FailureOutcome {}

        /**
         * The scan is not this agent's at that attempt: a report already applied, one about an
         * attempt since superseded, or a lease that lapsed first. Nothing was written.
         */
        record NoLongerYours() implements FailureOutcome {}
    }

    /**
     * A failure report's body, as the agent writes it. Unknown fields are a later agent's, and read past.
     *
     * @param kind {@code permanent} or {@code transient}; absent from an agent older than the field,
     *     and read as transient — see {@link FailureKind#fromWire}
     */
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    record FailureReport(Integer attempt, String reason, String kind) {}

    /**
     * Whether this agent takes part in the protocol at all — every route of it asks first.
     *
     * <p><b>Disabling an agent is how an administrator stops it without destroying its key</b>: its
     * row, labels and pinned keys stay, so it can be turned back on. The key still authenticates, so
     * this is the one place that stops a disabled agent claiming work, fetching rules or handing back
     * a result. It sat in the controller as a line of its guard; a second entry point to the
     * protocol would have had to know to copy it.
     *
     * @param agent as the principal carries it, read from its row on this request
     */
    public boolean admits(AgentView agent) {
        return agent.enabled();
    }

    /**
     * An agent's announcement, recorded as its heartbeat.
     *
     * <p>If this call answers, the URL, the key, the scope and the agent row are all correct —
     * that is, most of what can be misconfigured.
     */
    public Hello hello(AgentView agent, Announcement announcement) {
        String announced = announcement.contractVersion() == null ? "" : announcement.contractVersion();

        if (!AgentContract.isCompatible(announced)) {
            return new Hello.IncompatibleContract(announced);
        }

        // **Clipped to the columns, never refused.** This is the agent describing itself — a
        // hostname, a platform string, the version it was built as — and nobody can correct it from
        // this side: a refusal would drop the heartbeat, the agent would read as offline and stop
        // being given work, over a display field. Past the column the database used to refuse the
        // update instead, with the same outcome and a 500 in the agent's log. The value that decides
        // something, the contract version, is checked above and never clipped.
        agents.recordHeartbeat(
                agent.id(),
                clock.instant(),
                BoundedText.clip(text(announcement.hostname()), 255),
                BoundedText.clip(text(announcement.platform()), 255),
                BoundedText.clip(text(announcement.version()), 50),
                BoundedText.clip(text(announcement.scannerEngine()), 50),
                BoundedText.clip(text(announcement.capabilities()), BoundedText.TEXT_MAX),
                // Trimmed, as the compatibility check read it: padding it accepted would otherwise
                // overflow a column sized for the version itself.
                announced.trim());

        return new Hello.Accepted(AgentConcurrency.effective(agent.maxConcurrent()));
    }

    /**
     * Notes that the agent spoke — a poll for work, a lease renewal — without a write per request.
     *
     * <p><b>The hello and the claim used to be the only writers</b>, so an agent that was up,
     * polling every thirty seconds and simply finding no work, stopped being heard from at its last
     * claim: two minutes later the agents screen called a healthy agent offline, and an operator
     * reading it restarted something that was not broken. A poll is the sign of life an idle agent
     * gives, so it counts.
     *
     * <p><b>Once per {@link #SEEN_GRANULARITY} at most.</b> The principal was read from the row by
     * this very request, so a recent enough value is known without asking; the statement that
     * follows repeats the condition, so two polls racing on it cannot put an older instant back.
     */
    public void heardFrom(AgentView agent) {
        Instant now = clock.instant();
        Instant staleBefore = now.minus(SEEN_GRANULARITY);
        if (agent.lastSeenAt() != null && !agent.lastSeenAt().isBefore(staleBefore)) {
            return;
        }
        agents.recordSeen(agent.id(), now, staleBefore);
    }

    /**
     * Extends the lease of a scan entrusted to this agent, and counts the renewal as a sign of life:
     * an agent busy with one long scan polls nothing, and its heartbeats are all it says.
     *
     * @return false when the lease was taken over
     */
    public boolean renewLease(AgentView agent, long scanId) {
        heardFrom(agent);
        return dispatcher.renewAgentLease(scanId, agent);
    }

    /**
     * An agent's sealing key, accepted only on the word of the key an administrator pinned.
     *
     * <p><b>Why the pinned key and nothing else</b> (decision 0031). The sealing key crosses the
     * channel the sealing exists to distrust — a TLS-terminating proxy may sit on it. Believing an
     * announcement because it arrived would let that channel choose the key credentials are sealed
     * for. The result-signing key is the one thing the agent holds that the control plane learned
     * from somebody else, so it is what vouches. <b>No pinned key, no sealing key</b>: there is no
     * trust on first use to fall back on, because the pair is remade at every start and a key
     * trusted on first sight would have to be trusted again, unsigned, at the next.
     *
     * <p>The refusals that mean somebody may be trying — a signature that does not verify, a key
     * older than the one held — are audited, and the entry signals a SIEM event. The row is written
     * by one conditional statement, which has committed before the entry is recorded.
     */
    public SealingKey announceSealingKey(AgentView agent, SealingKeyAnnouncement announcement, RequestActor origin) {
        String key = text(announcement.publicKey());
        Long generation = announcement.generation();
        if (key == null || !SealedEnvelope.isUsablePublicKey(key) || generation == null || generation <= 0) {
            return new SealingKey.Unreadable();
        }

        String pinned = agent.signingPublicKey();
        if (pinned == null || pinned.isBlank()) {
            return new SealingKey.NotPinned();
        }

        if (!SealingKeyAttestation.verify(pinned, agent.id(), generation, key, announcement.signature())) {
            recordSealingKey(AuditOperation.AGENT_SEALING_KEY_REFUSED, agent, origin,
                    "Sealing key refused for agent \"" + agent.name() + "\": its signature does not verify against "
                            + "the pinned signing key. No credential is sealed for it.");
            return new SealingKey.NotVerified();
        }

        if (agents.acceptSealingKey(agent.id(), key, generation) == 0) {
            recordSealingKey(AuditOperation.AGENT_SEALING_KEY_REFUSED, agent, origin,
                    "Sealing key refused for agent \"" + agent.name() + "\": generation " + generation
                            + " is not newer than the key already accepted. No credential is sealed for it.");
            return new SealingKey.Stale();
        }

        boolean rotated = !key.equals(agent.sealingPublicKey());
        if (rotated) {
            recordSealingKey(AuditOperation.AGENT_SEALING_KEY_ACCEPTED, agent, origin,
                    "Sealing key accepted for agent \"" + agent.name() + "\", signed with its pinned key (generation "
                            + generation + "). Credentials delegated to it are sealed for this key.");
        }
        return new SealingKey.Accepted(rotated);
    }

    /**
     * The result of a scan executed elsewhere.
     *
     * <p>What the attestation guards is the operation described in {@link ResultAttestation}:
     * artifacts that are present and empty resolve a target's whole backlog of that type. An agent
     * with a pinned signing key must prove it is that agent; an agent without one behaves exactly
     * as before.
     *
     * <p><b>The body arrives as bytes, and that is what the signature covers.</b> Parsing first
     * and verifying the re-serialization would verify what the server chose to write.
     */
    public Submission submitResult(AgentView agent, long scanId, byte[] body, String signature, RequestActor origin) {
        if (!attested(agent, scanId, body, signature, origin)) {
            return new Submission.NotAttested();
        }

        ScanArtifacts artifacts;
        try {
            artifacts = json.readValue(body, ScanArtifacts.class);
        } catch (IOException unreadable) {
            return new Submission.Unreadable();
        }

        if (!dispatcher.acceptAgentResult(scanId, agent, artifacts)) {
            return new Submission.NoLongerYours();
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_RESULT_SUBMITTED,
                String.valueOf(scanId),
                "Result accepted from agent \"" + agent.name() + "\""
                        + (agent.signingPublicKey() == null ? " (not attested)." : ", attestation verified."),
                agent.name(),
                origin.ipAddress(),
                origin.userAgent()));

        return new Submission.Accepted();
    }

    /**
     * An agent's word that it could not run a scan it claimed, applied at once instead of when the
     * lease lapses — see {@link ScanDispatcher#reportAgentFailure} for what it does to the attempts.
     *
     * <p><b>Attested like a result</b>, under a context of its own: a report does not resolve anything,
     * but it spends one of the scan's attempts and fails the scan at the last. Unsigned from an agent
     * whose key is pinned, it would let a stolen API key keep any target from ever being scanned, so it
     * is refused and audited as a result would be.
     *
     * <p><b>The reason is scrubbed again here</b>, although the agent scrubbed it: the agent knows the
     * secrets it held and removes them by value, this side removes what has a secret's shape, and a
     * report is text from another machine on its way to every account that sees the target.
     */
    public FailureOutcome reportFailure(AgentView agent, long scanId, byte[] body, String signature, RequestActor origin) {
        String pinned = agent.signingPublicKey();
        if (pinned != null && !pinned.isBlank() && !ResultAttestation.verifyFailure(pinned, scanId, body, signature)) {
            audit.record(new AuditLogService.Record(
                    AuditOperation.AGENT_RESULT_REFUSED,
                    String.valueOf(scanId),
                    (signature == null || signature.isBlank()
                                    ? "Failure report submitted with no attestation"
                                    : "Failure report submitted with an attestation that does not verify")
                            + " by agent \"" + agent.name() + "\", whose signing key is pinned. The scan was left as it was.",
                    agent.name(),
                    origin.ipAddress(),
                    origin.userAgent()));
            return new FailureOutcome.NotAttested();
        }

        FailureReport report;
        try {
            report = json.readValue(body, FailureReport.class);
        } catch (IOException unreadable) {
            return new FailureOutcome.Unreadable();
        }
        if (report == null || report.attempt() == null || report.attempt() < 1) {
            return new FailureOutcome.Unreadable();
        }

        // A sign of life, like a renewal: the agent is up, it simply could not run this one.
        heardFrom(agent);
        String reason = FailureReason.scrub(report.reason());
        FailureKind kind = FailureKind.fromWire(report.kind());
        Optional<ScanDispatcher.AgentFailure> recorded = dispatcher.reportAgentFailure(
                scanId, agent, report.attempt(), kind, reason.isEmpty() ? "the agent gave no reason." : reason);
        if (recorded.isEmpty()) {
            return new FailureOutcome.NoLongerYours();
        }

        ScanDispatcher.AgentFailure failure = recorded.get();
        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_SCAN_FAILED,
                String.valueOf(scanId),
                "Agent \"" + agent.name() + "\" reported it could not run attempt " + failure.attempt() + " of "
                        + failure.maxAttempts() + " of the scan, a " + kind.wireName() + " failure"
                        + (pinned == null || pinned.isBlank() ? " (not attested)" : ", attestation verified")
                        + (failure.retried() ? "; back in the queue, not before " + failure.notBefore() + "." : "; the scan failed."),
                agent.name(),
                origin.ipAddress(),
                origin.userAgent()));
        return new FailureOutcome.Recorded(
                failure.retried(), failure.attempt(), failure.maxAttempts(), failure.permanent(), failure.notBefore());
    }

    /**
     * Whether a pinned key vouches for the result — true when none is pinned.
     *
     * <p><b>Pinning the key is the switch.</b> There is no second setting saying "and now enforce
     * it" — an operator who writes the key has said what they mean, and a control with an
     * enforcement flag of its own is a control somebody leaves in audit mode for a year.
     *
     * <p>The refusal is audited here, before the caller answers, because a probe that leaves no
     * trace is the one nobody investigates.
     */
    private boolean attested(AgentView agent, long scanId, byte[] body, String signature, RequestActor origin) {
        String pinned = agent.signingPublicKey();
        if (pinned == null || pinned.isBlank()) {
            return true;
        }
        if (ResultAttestation.verify(pinned, scanId, body, signature)) {
            return true;
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.AGENT_RESULT_REFUSED,
                String.valueOf(scanId),
                (signature == null || signature.isBlank()
                                ? "Result submitted with no attestation"
                                : "Result submitted with an attestation that does not verify")
                        + " by agent \"" + agent.name() + "\", whose signing key is pinned.",
                agent.name(),
                origin.ipAddress(),
                origin.userAgent()));
        return false;
    }

    private void recordSealingKey(AuditOperation operation, AgentView agent, RequestActor origin, String description) {
        audit.record(new AuditLogService.Record(
                operation,
                agent.id().toString(),
                description,
                agent.name(),
                origin.ipAddress(),
                origin.userAgent()));
    }

    private static String text(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
