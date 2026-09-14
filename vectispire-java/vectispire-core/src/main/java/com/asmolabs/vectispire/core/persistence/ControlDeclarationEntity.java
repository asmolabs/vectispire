package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * One line of an organisation's declaration of applicability.
 *
 * <p>The reasoning is in the migration and in {@code StatementOfApplicability}; what belongs here
 * is the storage decision. <b>The enums are stored as their names, not their ordinals</b>, because
 * a row in this table is read by a person doing an assessment and {@code applicability = 1} is not
 * a document. It also means inserting a value into an enum cannot silently re-label existing rows.
 *
 * <p>{@code controlId} is a free string rather than a foreign key, because the controls are an
 * enumeration in the jar and not a table. A declaration naming a control this build does not carry
 * is therefore storable, and is dropped when the statement is assembled — a revision of the
 * standard nobody has ported must not stop an organisation recording what it decided.
 */
@Entity
@Table(name = "t_control_declaration")
public class ControlDeclarationEntity {

    /** {@code SqlTypes.CHAR} for the reason spelt out on {@code GateVerdictEntity}. */
    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "framework", nullable = false, length = 32)
    private String framework;

    @Column(name = "control_id", nullable = false, length = 64)
    private String controlId;

    @Column(name = "applicability", nullable = false, length = 16)
    private String applicability;

    @Column(name = "justification", columnDefinition = "text")
    private String justification;

    @Column(name = "implementation", length = 32)
    private String implementation;

    @Column(name = "evidence_source", nullable = false, length = 16)
    private String evidenceSource;

    @Column(name = "external_evidence", columnDefinition = "text")
    private String externalEvidence;

    /** {@code owner} is a keyword on more engines than it is not; the column carries a prefix. */
    @Column(name = "control_owner")
    private String owner;

    @Column(name = "decided_by")
    private String decidedBy;

    @Column(name = "decided_at", nullable = false)
    private Instant decidedAt;

    @Column(name = "reviewed_at")
    private Instant reviewedAt;

    @Column(name = "review_due_at")
    private Instant reviewDueAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getFramework() {
        return framework;
    }

    public void setFramework(String framework) {
        this.framework = framework;
    }

    public String getControlId() {
        return controlId;
    }

    public void setControlId(String controlId) {
        this.controlId = controlId;
    }

    public String getApplicability() {
        return applicability;
    }

    public void setApplicability(String applicability) {
        this.applicability = applicability;
    }

    public String getJustification() {
        return justification;
    }

    public void setJustification(String justification) {
        this.justification = justification;
    }

    public String getImplementation() {
        return implementation;
    }

    public void setImplementation(String implementation) {
        this.implementation = implementation;
    }

    public String getEvidenceSource() {
        return evidenceSource;
    }

    public void setEvidenceSource(String evidenceSource) {
        this.evidenceSource = evidenceSource;
    }

    public String getExternalEvidence() {
        return externalEvidence;
    }

    public void setExternalEvidence(String externalEvidence) {
        this.externalEvidence = externalEvidence;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getDecidedBy() {
        return decidedBy;
    }

    public void setDecidedBy(String decidedBy) {
        this.decidedBy = decidedBy;
    }

    public Instant getDecidedAt() {
        return decidedAt;
    }

    public void setDecidedAt(Instant decidedAt) {
        this.decidedAt = decidedAt;
    }

    public Instant getReviewedAt() {
        return reviewedAt;
    }

    public void setReviewedAt(Instant reviewedAt) {
        this.reviewedAt = reviewedAt;
    }

    public Instant getReviewDueAt() {
        return reviewDueAt;
    }

    public void setReviewDueAt(Instant reviewDueAt) {
        this.reviewDueAt = reviewDueAt;
    }
}
