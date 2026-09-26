package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue;
import com.asmolabs.vectispire.common.domain.gate.GateIssue;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueRows;

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
        return forGate(IssueView.of(issue));
    }

    /**
     * The same, from the view another module holds — the one mapping, which the entity's overload
     * goes through: two copies would be two chances for the gate and the ticket sweep to disagree.
     */
    public static GateIssue forGate(IssueView issue) {
        return new GateIssue(
                issue.id(),
                IssueState.OPEN.wireName().equals(issue.state()),
                FindingType.fromWireName(issue.type()).orElse(null),
                Severity.of(issue.severity()),
                issue.identifier(),
                issue.packageName(),
                issue.fixVersions(),
                issue.isKev(),
                triageOf(issue));
    }

    /**
     * The same view, built from a projection instead of an entity.
     *
     * <p>Identical field for field — the mapping is duplicated rather than shared because the two
     * inputs have no common supertype, and inventing one to save nine lines would put an interface
     * on a persistence entity for the benefit of a query.
     */
    public static GateIssue forGate(IssueRows.GateRow row) {
        return new GateIssue(
                row.id() == null ? 0L : row.id(),
                IssueState.OPEN.wireName().equals(row.state()),
                FindingType.fromWireName(row.type()).orElse(null),
                Severity.of(row.severity()),
                row.identifier(),
                row.packageName(),
                row.fixVersions(),
                row.isKev(),
                TriageStatus.fromWireName(row.triageStatus()).orElse(TriageStatus.UNDER_REVIEW));
    }

    /** What a ticket's title and body read. */
    public static TicketableIssue forTicket(IssueEntity issue) {
        return forTicket(IssueView.of(issue));
    }

    /** The same, from the view — the one mapping. */
    public static TicketableIssue forTicket(IssueView issue) {
        return new TicketableIssue(
                issue.id(),
                FindingType.fromWireName(issue.type()).orElse(null),
                issue.identifier(),
                Severity.of(issue.severity()),
                issue.packageName(),
                issue.packageVersion(),
                issue.fixVersions(),
                FixState.fromWireName(issue.fixState()).orElse(FixState.UNKNOWN),
                directnessOf(issue),
                issue.filePath(),
                issue.line(),
                issue.isKev(),
                issue.epssScore(),
                issue.link(),
                issue.description(),
                issue.fingerprint());
    }

    /**
     * An unreadable triage reads as "under review", never as a dismissal.
     *
     * <p>The asymmetry is the point: a value nobody recognizes must leave the issue in the
     * backlog. Reading it as {@code NOT_AFFECTED} would make a row written by a later version —
     * or by hand — silently disappear from every gate and every ticket sweep.
     */
    private static TriageStatus triageOf(IssueView issue) {
        return TriageStatus.fromWireName(issue.triageStatus()).orElse(TriageStatus.UNDER_REVIEW);
    }

    /**
     * {@code null} is unknown, and stays unknown.
     *
     * <p>A container scan cannot tell a direct dependency from a transitive one, and reading the
     * absence as "transitive" would put a confident wrong answer in a ticket somebody acts on.
     */
    private static Directness directnessOf(IssueView issue) {
        if (issue.isDirectDependency() == null) {
            return Directness.UNKNOWN;
        }
        return issue.isDirectDependency() ? Directness.DIRECT : Directness.TRANSITIVE;
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
        return forExport(IssueView.of(issue));
    }

    /** The same, from the view — the one mapping. */
    public static ExportableIssue forExport(IssueView issue) {
        return ExportableIssue.builder()
                .id(issue.id())
                .fingerprint(issue.fingerprint())
                .type(FindingType.fromWireName(issue.type()).orElse(null))
                .identifier(issue.identifier())
                .severity(Severity.of(issue.severity()))
                .cvssScore(issue.cvssScore())
                .epssScore(issue.epssScore())
                .kev(issue.isKev())
                .packageName(issue.packageName())
                .packageVersion(issue.packageVersion())
                .purl(issue.purl())
                .directness(directnessOf(issue))
                .filePath(issue.filePath())
                .line(issue.line())
                .fixState(FixState.fromWireName(issue.fixState()).orElse(FixState.UNKNOWN))
                .fixVersions(issue.fixVersions())
                .link(issue.link())
                .description(issue.description())
                .resolved(IssueState.RESOLVED.wireName().equals(issue.state()))
                .triageStatus(triageOf(issue))
                .triageJustification(issue.triageJustification())
                .triageComment(issue.triageComment())
                .triagedBy(issue.triagedBy())
                .triagedAt(issue.triagedAt())
                .triageExpiresAt(issue.triageExpiresAt())
                .firstSeenAt(issue.firstSeenAt())
                .lastSeenAt(issue.lastSeenAt())
                .timesSeen(issue.timesSeen())
                .build();
    }
}
