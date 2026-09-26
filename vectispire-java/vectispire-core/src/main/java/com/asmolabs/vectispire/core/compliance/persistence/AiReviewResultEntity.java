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

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "response")
    private String response;

    @Column(name = "status", length = 50, nullable = false)
    private String status;

    @Column(name = "error", length = 500)
    private String error;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

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
}
