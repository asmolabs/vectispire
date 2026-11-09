package com.asmolabs.vectispire.core.reportplugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * One manifest a report plugin had, keyed by its digest: the manifest itself never rewritten, its approval
 * and its withdrawal beside it.
 *
 * <p>The digest is computed from the manifest ({@code ReportPluginManifest.digest}), so the key and the
 * content cannot disagree; a run and a document's provenance name it (lots R3, R4), and a withdrawal marks
 * every document it produced (lot R7).
 */
@Entity
@Table(name = "t_report_plugin_manifest")
public class ReportPluginManifestEntity {

    @Id
    @Column(name = "digest", length = 64, nullable = false)
    private String digest;

    @Column(name = "plugin_id", length = 40, nullable = false)
    private String pluginId;

    /** The manifest as JSON, in the form the governor registered it. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "manifest", nullable = false)
    private String manifest;

    /** A {@code ReportPluginManifestStatus} wire name. */
    @Column(name = "status", length = 20, nullable = false)
    private String status;

    @Column(name = "registered_at", nullable = false)
    private Instant registeredAt;

    @Column(name = "registered_by", length = 255, nullable = false)
    private String registeredBy;

    /** The account four-eyes compares an approver with — an id, since a user name can be reused. */
    @Column(name = "registered_by_id", nullable = false)
    private Long registeredById;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    @Column(name = "approved_by_id")
    private Long approvedById;

    /** Whether four-eyes applied when it was approved; null until then. */
    @Column(name = "approval_four_eyes")
    private Boolean approvalFourEyes;

    @Column(name = "withdrawn_at")
    private Instant withdrawnAt;

    @Column(name = "withdrawn_by", length = 255)
    private String withdrawnBy;

    @Column(name = "withdrawal_justification", length = 500)
    private String withdrawalJustification;

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getPluginId() {
        return pluginId;
    }

    public void setPluginId(String pluginId) {
        this.pluginId = pluginId;
    }

    public String getManifest() {
        return manifest;
    }

    public void setManifest(String manifest) {
        this.manifest = manifest;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getRegisteredAt() {
        return registeredAt;
    }

    public void setRegisteredAt(Instant registeredAt) {
        this.registeredAt = registeredAt;
    }

    public String getRegisteredBy() {
        return registeredBy;
    }

    public void setRegisteredBy(String registeredBy) {
        this.registeredBy = registeredBy;
    }

    public Long getRegisteredById() {
        return registeredById;
    }

    public void setRegisteredById(Long registeredById) {
        this.registeredById = registeredById;
    }

    public Instant getApprovedAt() {
        return approvedAt;
    }

    public void setApprovedAt(Instant approvedAt) {
        this.approvedAt = approvedAt;
    }

    public String getApprovedBy() {
        return approvedBy;
    }

    public void setApprovedBy(String approvedBy) {
        this.approvedBy = approvedBy;
    }

    public Long getApprovedById() {
        return approvedById;
    }

    public void setApprovedById(Long approvedById) {
        this.approvedById = approvedById;
    }

    public Boolean getApprovalFourEyes() {
        return approvalFourEyes;
    }

    public void setApprovalFourEyes(Boolean approvalFourEyes) {
        this.approvalFourEyes = approvalFourEyes;
    }

    public Instant getWithdrawnAt() {
        return withdrawnAt;
    }

    public void setWithdrawnAt(Instant withdrawnAt) {
        this.withdrawnAt = withdrawnAt;
    }

    public String getWithdrawnBy() {
        return withdrawnBy;
    }

    public void setWithdrawnBy(String withdrawnBy) {
        this.withdrawnBy = withdrawnBy;
    }

    public String getWithdrawalJustification() {
        return withdrawalJustification;
    }

    public void setWithdrawalJustification(String withdrawalJustification) {
        this.withdrawalJustification = withdrawalJustification;
    }
}
