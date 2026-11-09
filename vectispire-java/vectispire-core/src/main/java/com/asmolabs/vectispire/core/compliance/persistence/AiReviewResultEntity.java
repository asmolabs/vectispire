package com.asmolabs.vectispire.core.compliance.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * What a model was asked and what it answered.
 *
 * <p>The raw response is kept beside the structured findings, because the parser is
 * best-effort: a malformed answer degrades to no findings, and without the text there would be
 * nothing left to look at.
 */
@Entity
@Table(name = "t_ai_review_result")
public class AiReviewResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    /**
     * The repository the scan was of, copied from it when the review is requested (V62) so that the
     * latest review of a repository is read without joining {@code scanning}'s table. A scan never
     * changes target, and the review goes with its scan, so the copy cannot disagree with it.
     */
    @Column(name = "repo_id")
    private Long repoId;

    @Column(name = "model", length = 255, nullable = false)
    private String model;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "prompt", nullable = false)
    private String prompt;

    /**
     * What the model was actually shown: the evidence digest, not the instruction.
     *
     * <p>The prompt above is static. This is the half that decides what the prose says, and it was
     * computed, handed over and dropped — which left the report unverifiable in the only way that
     * matters, since the issues it was built from have moved on and nobody can recompute it.
     */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "inputs")
    private String inputs;

    /**
     * The identifiers of the findings {@link #getInputs() inputs} lists, as a JSON array, or null on a
     * review written before V84. What the report's links may point at, and the only thing: an
     * identifier the prose cites and this does not hold was not shown to the model.
     */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "evidence_identifiers")
    private String evidenceIdentifiers;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "response")
    private String response;

    @Column(name = "status", length = 50, nullable = false)
    private String status;

    @Column(name = "error", length = 500)
    private String error;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    /**
     * When a {@code running} review stops being waited for: the model's timeout and a margin, from
     * the request. Null once settled, and on every row written before reviews had a running state.
     */
    @Column(name = "deadline_at")
    private Instant deadlineAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
    }

    public Long getRepoId() {
        return repoId;
    }

    public void setRepoId(Long repoId) {
        this.repoId = repoId;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getPrompt() {
        return prompt;
    }

    public String getInputs() {
        return inputs;
    }

    public void setInputs(String inputs) {
        this.inputs = inputs;
    }

    public String getEvidenceIdentifiers() {
        return evidenceIdentifiers;
    }

    public void setEvidenceIdentifiers(String evidenceIdentifiers) {
        this.evidenceIdentifiers = evidenceIdentifiers;
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getDeadlineAt() {
        return deadlineAt;
    }

    public void setDeadlineAt(Instant deadlineAt) {
        this.deadlineAt = deadlineAt;
    }
}
