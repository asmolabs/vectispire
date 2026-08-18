package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.dependencies.Directness;
import com.asmolabs.zanshin.common.domain.exports.ExportableIssue;
import com.asmolabs.zanshin.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.zanshin.common.domain.gate.GateIssue;
import com.asmolabs.zanshin.common.domain.gate.GatePolicy;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution.StoredPolicy;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.tickets.Tickets.TicketableIssue;
import com.asmolabs.zanshin.core.persistence.GatePolicyEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;

/**
 * Turning a stored row into the narrow shape a domain rule reads.
 *
 * <p>One place, because every one of these conversions decides something. A triage read as
 * {@code null} turns a dismissal into an open finding; a severity read leniently as {@code
 * UNKNOWN} ranks last and slips under every threshold. Scattering them across the callers is
 * how two screens come to disagree about the same row.
 */
public final class IssueViews {

    private IssueViews() {}

    /** What the gate reads. Deliberately narrower than the entity. */
    public static GateIssue forGate(IssueEntity issue) {
        return new GateIssue(
                issue.getId(),
                IssueState.OPEN.wireName().equals(issue.getState()),
                FindingType.fromWireName(issue.getType()).orElse(null),
                Severity.of(issue.getSeverity()),
                issue.getIdentifier(),
                issue.getPackageName(),
                issue.getFixVersions(),
                issue.getIsKev(),
                triageOf(issue));
    }

    /** What a ticket's title and body read. */
    public static TicketableIssue forTicket(IssueEntity issue) {
        return new TicketableIssue(
                issue.getId(),
                FindingType.fromWireName(issue.getType()).orElse(null),
                issue.getIdentifier(),
                Severity.of(issue.getSeverity()),
                issue.getPackageName(),
                issue.getPackageVersion(),
                issue.getFixVersions(),
                FixState.fromWireName(issue.getFixState()).orElse(FixState.UNKNOWN),
                directnessOf(issue),
                issue.getFilePath(),
                issue.getLine(),
                issue.getIsKev(),
                issue.getEpssScore(),
                issue.getLink(),
                issue.getDescription(),
                issue.getFingerprint());
    }

    /** A stored gate policy, with the version the API reports back to a pipeline. */
    public static StoredPolicy storedPolicy(GatePolicyEntity policy) {
        return new StoredPolicy(
                new GatePolicy(
                        Severity.of(policy.getFailOnSeverity()),
                        policy.getFailOnKev(),
                        policy.getFixableOnly(),
                        policy.getIncludeTriaged(),
                        policy.getIncludeAiReview()),
                policy.getVersion());
    }

    /**
     * An unreadable triage reads as "under review", never as a dismissal.
     *
     * <p>The asymmetry is the point: a value nobody recognizes must leave the issue in the
     * backlog. Reading it as {@code NOT_AFFECTED} would make a row written by a later version —
     * or by hand — silently disappear from every gate and every ticket sweep.
     */
    private static TriageStatus triageOf(IssueEntity issue) {
        return TriageStatus.fromWireName(issue.getTriageStatus()).orElse(TriageStatus.UNDER_REVIEW);
    }

    /**
     * {@code null} is unknown, and stays unknown.
     *
     * <p>A container scan cannot tell a direct dependency from a transitive one, and reading the
     * absence as "transitive" would put a confident wrong answer in a ticket somebody acts on.
     */
    private static Directness directnessOf(IssueEntity issue) {
        if (issue.getIsDirectDependency() == null) {
            return Directness.UNKNOWN;
        }
        return issue.getIsDirectDependency() ? Directness.DIRECT : Directness.TRANSITIVE;
    }

    /**
     * An issue as the three export formats read it.
     *
     * <p>Instants are handed over as instants and canonicalized by the export itself. The
     * NestJS version converted them at every call site, and a document handed to an auditor
     * carried "Mon Aug 10 2026 …" the day one site was missed — offset by the machine's timezone
     * on top of that.
     */
    public static ExportableIssue forExport(IssueEntity issue) {
        return ExportableIssue.builder()
                .id(issue.getId())
                .fingerprint(issue.getFingerprint())
                .type(FindingType.fromWireName(issue.getType()).orElse(null))
                .identifier(issue.getIdentifier())
                .severity(Severity.of(issue.getSeverity()))
                .cvssScore(issue.getCvssScore())
                .epssScore(issue.getEpssScore())
                .kev(issue.getIsKev())
                .packageName(issue.getPackageName())
                .packageVersion(issue.getPackageVersion())
                .purl(issue.getPurl())
                .directness(directnessOf(issue))
                .filePath(issue.getFilePath())
                .line(issue.getLine())
                .fixState(FixState.fromWireName(issue.getFixState()).orElse(FixState.UNKNOWN))
                .fixVersions(issue.getFixVersions())
                .link(issue.getLink())
                .description(issue.getDescription())
                .resolved(IssueState.RESOLVED.wireName().equals(issue.getState()))
                .triageStatus(triageOf(issue))
                .triageJustification(issue.getTriageJustification())
                .triageComment(issue.getTriageComment())
                .triagedBy(issue.getTriagedBy())
                .triagedAt(issue.getTriagedAt())
                .triageExpiresAt(issue.getTriageExpiresAt())
                .firstSeenAt(issue.getFirstSeenAt())
                .lastSeenAt(issue.getLastSeenAt())
                .timesSeen(issue.getTimesSeen())
                .build();
    }
}
