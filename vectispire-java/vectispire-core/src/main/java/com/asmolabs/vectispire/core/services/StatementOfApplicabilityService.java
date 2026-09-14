package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Applicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.EvidenceSource;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Implementation;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Statement;
import com.asmolabs.vectispire.core.persistence.ControlDeclarationEntity;
import com.asmolabs.vectispire.core.repositories.ControlDeclarations;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Holds the declaration, and sets it against what the estate measures.
 *
 * <p>The reconciliation itself is pure and lives in {@link StatementOfApplicability}; what is here
 * is storage, validation and the audit entry. The split is deliberate — the rule deciding what
 * counts as a contradiction is the part somebody will argue with in a meeting, and it is testable
 * without a database.
 */
@Service
public class StatementOfApplicabilityService {

    private final ControlDeclarations declarations;
    private final ComplianceService compliance;
    private final AuditLogService audit;
    private final Clock clock;

    public StatementOfApplicabilityService(
            ControlDeclarations declarations,
            ComplianceService compliance,
            AuditLogService audit,
            Clock clock) {
        this.declarations = declarations;
        this.compliance = compliance;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * One framework's declaration, reconciled against its evaluation.
     *
     * <p><b>The allowance narrows the measurement, never the declaration.</b> A declaration says
     * what the organisation claims about a control and belongs to nobody's estate; the evaluation
     * it is set against is the caller's. A restricted reader therefore sees the whole document and
     * a reconciliation drawn from their slice — which is the honest combination, and the reason
     * the statement carries the evaluation's own coverage wherever it is exported.
     */
    @Transactional(readOnly = true)
    public Statement statement(ComplianceFramework framework, Visibility allowed) {
        return StatementOfApplicability.reconcile(
                compliance.getEvaluation(framework, allowed), declared(framework), clock.instant());
    }

    /** Every framework's declaration, for the bundle and the ISMS dashboard. */
    @Transactional(readOnly = true)
    public List<Statement> statements(Visibility allowed) {
        return java.util.Arrays.stream(ComplianceFramework.values())
                .map(framework -> statement(framework, allowed))
                .toList();
    }

    /**
     * What an operator submits for one control.
     *
     * @param reviewDueAt when the line must be confirmed again; null leaves it unscheduled
     */
    public record Submission(
            Applicability applicability,
            String justification,
            Implementation implementation,
            EvidenceSource evidenceSource,
            String externalEvidence,
            String owner,
            Instant reviewDueAt) {}

    /**
     * Writes or revises one line, and says so in the audit log.
     *
     * <p><b>Two refusals rather than one, and both are the standard's.</b> An exclusion with no
     * justification is what clause 6.1.3 d forbids; evidence declared to live elsewhere with no
     * pointer to where is the same failure in a different place — a line that opts out of the
     * measurement and then names nothing in its stead is not a declaration, it is a blank.
     *
     * <p>Refused at the door rather than reported as a divergence, because these two are errors in
     * the document and not disagreements with the estate. The reconciliation still reports
     * {@code EXCLUDED_WITHOUT_JUSTIFICATION}: rows predating this validation, or written straight
     * into the database, must still be visible rather than silently well-formed.
     *
     * <p><b>Deliberately not in a transaction.</b> The audit entry is written with {@code
     * REQUIRES_NEW} — an attempt must survive a rollback of the thing attempted — and a second
     * connection writing inside an open snapshot is what SQLite refuses outright. So this method
     * follows the convention the rest of the codebase already keeps: persist, then audit, neither
     * wrapping the other.
     *
     * <p>Which leaves the read and the write unatomic, and the unique index on (framework,
     * control) is the arbiter. Two people declaring the same control in the same instant is a race
     * one of them loses with a constraint violation rather than a document carrying the control
     * twice — the right way round for a register whose whole value is that it says one thing.
     *
     * @param actor the username to record; the claim's author is the point of the entry
     */
    public Declaration declare(
            ComplianceFramework framework, String controlId, Submission submission, String actor) {

        // A body missing either enum would otherwise reach the reconciliation as a half-written
        // line and be reported as a divergence — a document defect dressed up as a disagreement
        // with the estate.
        if (submission.applicability() == null || submission.evidenceSource() == null) {
            throw new IllegalArgumentException(
                    "A declaration says two things at minimum: whether the control applies, and where its "
                            + "evidence lives.");
        }
        if (submission.applicability() == Applicability.APPLICABLE && submission.implementation() == null) {
            throw new IllegalArgumentException(
                    "An applicable control needs an implementation state: claiming it applies and saying "
                            + "nothing about whether it is in place is the omission the document exists to close.");
        }
        if (submission.applicability() == Applicability.EXCLUDED && isBlank(submission.justification())) {
            throw new IllegalArgumentException(
                    "An excluded control needs a justification: ISO 27001 clause 6.1.3 d requires one.");
        }
        if (submission.evidenceSource() != EvidenceSource.VECTISPIRE
                && isBlank(submission.externalEvidence())) {
            throw new IllegalArgumentException(
                    "Evidence held outside Vectispire must say where: name the document, register or review.");
        }

        Instant now = clock.instant();
        ControlDeclarationEntity row = declarations
                .findByFrameworkAndControlId(framework.name(), controlId)
                .orElseGet(() -> {
                    ControlDeclarationEntity fresh = new ControlDeclarationEntity();
                    fresh.setId(UUID.randomUUID());
                    fresh.setFramework(framework.name());
                    fresh.setControlId(controlId);
                    return fresh;
                });

        row.setApplicability(submission.applicability().name());
        row.setJustification(submission.justification());
        // An excluded control has nothing to implement, and a stale implementation left behind on
        // a line that was switched to excluded would read as a claim the organisation withdrew.
        row.setImplementation(submission.applicability() == Applicability.EXCLUDED
                ? null
                : name(submission.implementation()));
        row.setEvidenceSource(submission.evidenceSource().name());
        row.setExternalEvidence(submission.externalEvidence());
        row.setOwner(submission.owner());
        row.setDecidedBy(actor);
        row.setDecidedAt(now);
        // Writing the line *is* confirming it holds: a revision that left the previous review date
        // in place would show a claim decided today and last checked a year ago.
        row.setReviewedAt(now);
        row.setReviewDueAt(submission.reviewDueAt());

        ControlDeclarationEntity saved = declarations.save(row);

        audit.record(AuditLogService.Record.of(
                AuditOperation.CONTROL_DECLARED,
                framework.name() + "/" + controlId,
                describe(framework, controlId, submission),
                actor));

        return toDomain(saved);
    }

    /** Lines whose review has lapsed, across every framework. */
    @Transactional(readOnly = true)
    public List<Declaration> reviewOverdue() {
        return declarations.findReviewOverdue(clock.instant()).stream()
                .map(StatementOfApplicabilityService::toDomain)
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    private List<Declaration> declared(ComplianceFramework framework) {
        return declarations.findByFramework(framework.name()).stream()
                .map(StatementOfApplicabilityService::toDomain)
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    private static String describe(
            ComplianceFramework framework, String controlId, Submission submission) {
        return submission.applicability() == Applicability.EXCLUDED
                ? "Excluded " + controlId + " from " + framework.getTitle() + ": " + submission.justification()
                : "Declared " + controlId + " of " + framework.getTitle() + " applicable, "
                        + submission.implementation() + ", evidenced " + submission.evidenceSource();
    }

    /**
     * Null for a row whose framework this build no longer carries.
     *
     * <p>Dropped rather than thrown on: a framework removed from the enum between two releases
     * would otherwise make the whole statement unreadable, and a document that will not open is a
     * worse outcome than one missing a line for a standard nobody evaluates any more.
     */
    private static Declaration toDomain(ControlDeclarationEntity row) {
        ComplianceFramework framework;
        try {
            framework = ComplianceFramework.valueOf(row.getFramework());
        } catch (IllegalArgumentException unknown) {
            return null;
        }
        return new Declaration(
                framework,
                row.getControlId(),
                Applicability.valueOf(row.getApplicability()),
                row.getJustification(),
                row.getImplementation() == null ? null : Implementation.valueOf(row.getImplementation()),
                EvidenceSource.valueOf(row.getEvidenceSource()),
                row.getExternalEvidence(),
                row.getOwner(),
                row.getDecidedBy(),
                row.getDecidedAt(),
                row.getReviewedAt(),
                row.getReviewDueAt());
    }

    private static String name(Implementation implementation) {
        return implementation == null ? null : implementation.name();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
