package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.Instant;

/**
 * A stored gate policy, versioned rather than updated.
 *
 * <p>A new version is inserted and the previous one deactivated, so "which rules failed that
 * build in March" stays answerable. {@code isActive} is nullable for the same reason the rule
 * set's is: a unique index counts NULLs as distinct, so only the active row collides.
 */
@Entity
@Table(name = "t_gate_policy")
public class GatePolicyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "target_kind", length = 20, nullable = false)
    private String targetKind;

    @Column(name = "target_id", nullable = false)
    private Long targetId;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "is_active")
    private Boolean isActive;

    @Column(name = "fail_on_severity", length = 20)
    private String failOnSeverity;

    @Column(name = "fail_on_kev", nullable = false)
    private boolean failOnKev;

    @Column(name = "fixable_only", nullable = false)
    private boolean fixableOnly;

    @Column(name = "include_triaged", nullable = false)
    private boolean includeTriaged;

    @Column(name = "include_ai_review", nullable = false)
    private boolean includeAiReview;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "note")
    private String note;

    @Column(name = "created_by", length = 255)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTargetKind() {
        return targetKind;
    }

    public void setTargetKind(String targetKind) {
        this.targetKind = targetKind;
    }

    public Long getTargetId() {
        return targetId;
    }

    public void setTargetId(Long targetId) {
        this.targetId = targetId;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public String getFailOnSeverity() {
        return failOnSeverity;
    }

    public void setFailOnSeverity(String failOnSeverity) {
        this.failOnSeverity = failOnSeverity;
    }

    public boolean getFailOnKev() {
        return failOnKev;
    }

    public void setFailOnKev(boolean failOnKev) {
        this.failOnKev = failOnKev;
    }

    public boolean getFixableOnly() {
        return fixableOnly;
    }

    public void setFixableOnly(boolean fixableOnly) {
        this.fixableOnly = fixableOnly;
    }

    public boolean getIncludeTriaged() {
        return includeTriaged;
    }

    public void setIncludeTriaged(boolean includeTriaged) {
        this.includeTriaged = includeTriaged;
    }

    public boolean getIncludeAiReview() {
        return includeAiReview;
    }

    public void setIncludeAiReview(boolean includeAiReview) {
        this.includeAiReview = includeAiReview;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
