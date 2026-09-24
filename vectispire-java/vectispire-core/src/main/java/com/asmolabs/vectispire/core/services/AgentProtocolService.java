package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Clock;
import org.springframework.stereotype.Service;

/**
 * What the control plane decides when a remote agent speaks: whether its announcement is
 * acceptable, and whether a result it hands back is.
 *
 * <p>The agent is already authenticated when it gets here — that is the controller's, from the
 * principal. The outcomes are closed sets rather than exceptions because each one is a distinct
 * answer the agent acts on (update yourself, give up this scan, sign your results), and the
 * status each maps to is the protocol's to state, next to the route.
 */
@Service
public class AgentProtocolService {

    private final Agents agents;
    private final ScanDispatcher dispatcher;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final Clock clock;

    public AgentProtocolService(
            Agents agents, ScanDispatcher dispatcher, AuditLogService audit, ObjectMapper json, Clock clock) {
        this.agents = agents;
        this.dispatcher = dispatcher;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
    }

    public record Announcement(
            String contractVersion,
            String sealingPublicKey,
            String hostname,
            String platform,
            String version,
            String scannerEngine,
            String capabilities) {}

    public sealed interface Hello {
        /** @param announced the version the agent claimed, empty when it claimed none */
        record IncompatibleContract(String announced) implements Hello {}

        record Accepted() implements Hello {}
    }

    public sealed interface Submission {
        record Accepted() implements Submission {}

        /** A signing key is pinned for this agent and the body does not carry its signature. */
        record NotAttested() implements Submission {}

        record Unreadable() implements Submission {}

        /** The lease was taken over while the agent worked; its results were discarded. */
        record NoLongerYours() implements Submission {}
    }

    /**
     * An agent's announcement, recorded as its heartbeat.
     *
     * <p>If this call answers, the URL, the key, the scope and the agent row are all correct —
     * that is, most of what can be misconfigured.
     */
    public Hello hello(AgentEntity agent, Announcement announcement) {
        String announced = announcement.contractVersion() == null ? "" : announcement.contractVersion();

        if (!AgentContract.isCompatible(announced)) {
            return new Hello.IncompatibleContract(announced);
        }

        // **Refused when unusable, rather than stored as it stands.** An unreadable value would
        // raise in the middle of a claim; `null` simply drops this agent back to the earlier
        // behaviour — a clear key over an encrypted link — which is a degraded mode, not a
        // failure.
        String sealingKey = text(announcement.sealingPublicKey());
        if (sealingKey != null && !SealedEnvelope.isUsablePublicKey(sealingKey)) {
            throw new IllegalArgumentException("The announced sealing key is not a readable X25519 public key.");
        }

        agents.recordHeartbeat(
                agent.getId(),
                clock.instant(),
                text(announcement.hostname()),
                text(announcement.platform()),
                text(announcement.version()),
                text(announcement.scannerEngine()),
                text(announcement.capabilities()),
                announced,
                sealingKey);

        return new Hello.Accepted();
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
    public Submission submitResult(AgentEntity agent, long scanId, byte[] body, String signature, RequestActor origin) {
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
                "Result accepted from agent \"" + agent.getName() + "\""
                        + (agent.getSigningPublicKey() == null ? " (not attested)." : ", attestation verified."),
                agent.getName(),
                origin.ipAddress(),
                origin.userAgent()));

        return new Submission.Accepted();
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
    private boolean attested(AgentEntity agent, long scanId, byte[] body, String signature, RequestActor origin) {
        String pinned = agent.getSigningPublicKey();
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
                        + " by agent \"" + agent.getName() + "\", whose signing key is pinned.",
                agent.getName(),
                origin.ipAddress(),
                origin.userAgent()));
        return false;
    }

    private static String text(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
