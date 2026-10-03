package com.asmolabs.vectispire.core.reportplugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;

/**
 * A registered report plugin (decision 0035 §4): its id, the manifest digest a run uses and the one awaiting
 * approval.
 *
 * <p><b>Versioned.</b> Every write is a read, a decision and a save — an approval checks that the digest is
 * still the pending one, an update replaces it — and two of them interleaving would let an approval install
 * a digest an update had just set aside. The revision makes the second writer fail instead of winning.
 */
@Entity
@Table(name = "t_report_plugin")
public class ReportPluginEntity {

    @Id
    @Column(name = "id", length = 40, nullable = false)
    private String id;

    @Column(name = "name", length = 100, nullable = false)
    private String name;

    @Column(name = "approved_digest", length = 64)
    private String approvedDigest;

    @Column(name = "pending_digest", length = 64)
    private String pendingDigest;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled;

    @Version
    @Column(name = "revision", nullable = false)
    private Long revision;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "created_by", length = 255, nullable = false)
    private String createdBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "updated_by", length = 255, nullable = false)
    private String updatedBy;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getApprovedDigest() {
        return approvedDigest;
    }

    public void setApprovedDigest(String approvedDigest) {
        this.approvedDigest = approvedDigest;
    }

    public String getPendingDigest() {
        return pendingDigest;
    }

    public void setPendingDigest(String pendingDigest) {
        this.pendingDigest = pendingDigest;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Long getRevision() {
        return revision;
    }

    public void setRevision(Long revision) {
        this.revision = revision;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }
}
