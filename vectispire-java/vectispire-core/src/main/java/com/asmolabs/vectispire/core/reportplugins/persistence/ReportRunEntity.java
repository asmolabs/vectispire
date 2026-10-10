package com.asmolabs.vectispire.core.reportplugins.persistence;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
 * One report run (decision 0035 §2): requested for a project, claimed by the control plane's executor, and what
 * came of it — with the provenance the run knows, each a column so that the audit entry, the screen and the
 * package's signed provenance ({@code ReportProvenance}) read one record. {@code activeKey} is set while the run is pending or running and cleared when
 * it ends: unique, it keeps one run of a plugin per project at a time.
 */
@Entity
@Table(name = "t_report_run")
public class ReportRunEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "project_name", length = 255)
    private String projectName;

    @Column(name = "plugin_id", length = 40, nullable = false)
    private String pluginId;

    @Column(name = "state", length = 20, nullable = false)
    private String state;

    @Column(name = "reason", length = 40)
    private String reason;

    @Column(name = "detail", length = 2000)
    private String detail;

    @Column(name = "active_key", length = 80)
    private String activeKey;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt;

    @Column(name = "requested_by", length = 255, nullable = false)
    private String requestedBy;

    @Column(name = "requested_by_id", nullable = false)
    private Long requestedById;

    @Column(name = "requester_locale", length = 35)
    private String requesterLocale;

    @Column(name = "claimed_by", length = 100)
    private String claimedBy;

    @Column(name = "lease_expires_at")
    private Instant leaseExpiresAt;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "exported_at")
    private Instant exportedAt;

    @Column(name = "finished_at")
    private Instant finishedAt;

    @Column(name = "manifest_digest", length = 64)
    private String manifestDigest;

    @Column(name = "image_digest", length = 71)
    private String imageDigest;

    @Column(name = "signer_identity", length = 500)
    private String signerIdentity;

    @Column(name = "signer_issuer", length = 500)
    private String signerIssuer;

    @Column(name = "signer_key_sha256", length = 64)
    private String signerKeySha256;

    @Column(name = "export_schema_version", length = 10)
    private String exportSchemaVersion;

    @Column(name = "export_sha256", length = 64)
    private String exportSha256;

    @Column(name = "export_size")
    private Long exportSize;

    /** {@code ReportRunTargets}' text: what the export carried; null on a run from before V87 (decision 0042). */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "export_targets")
    private String exportTargets;

    @Column(name = "exit_code")
    private Integer exitCode;

    @Column(name = "output_size")
    private Long outputSize;

    @Column(name = "output_sha256", length = 64)
    private String outputSha256;

    @Column(name = "product_version", length = 100)
    private String productVersion;

    @Column(name = "output_media_type", length = 120)
    private String outputMediaType;

    @Column(name = "signing_key_id", length = 64)
    private String signingKeyId;

    @Column(name = "package_sha256", length = 64)
    private String packageSha256;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getProjectId() {
        return projectId;
    }

    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getPluginId() {
        return pluginId;
    }

    public void setPluginId(String pluginId) {
        this.pluginId = pluginId;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    /** The queue's bookkeeping, not the run's record: {@code EntityViewsTest} is told the view leaves it out. */
    @JsonIgnore
    public String getActiveKey() {
        return activeKey;
    }

    public void setActiveKey(String activeKey) {
        this.activeKey = activeKey;
    }

    public Instant getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(Instant requestedAt) {
        this.requestedAt = requestedAt;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public void setRequestedBy(String requestedBy) {
        this.requestedBy = requestedBy;
    }

    /** The requester's account id, which the claim reads the account again by; the view names the requester. */
    @JsonIgnore
    public Long getRequestedById() {
        return requestedById;
    }

    public void setRequestedById(Long requestedById) {
        this.requestedById = requestedById;
    }

    /** The language the export states for its requester; the export says it, the view need not. */
    @JsonIgnore
    public String getRequesterLocale() {
        return requesterLocale;
    }

    public void setRequesterLocale(String requesterLocale) {
        this.requesterLocale = requesterLocale;
    }

    /** The executor holding the run, by its own name for itself — the queue's, not the record's. */
    @JsonIgnore
    public String getClaimedBy() {
        return claimedBy;
    }

    public void setClaimedBy(String claimedBy) {
        this.claimedBy = claimedBy;
    }

    /** The queue's: when a silent executor's run is failed as lost. */
    @JsonIgnore
    public Instant getLeaseExpiresAt() {
        return leaseExpiresAt;
    }

    public void setLeaseExpiresAt(Instant leaseExpiresAt) {
        this.leaseExpiresAt = leaseExpiresAt;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Instant startedAt) {
        this.startedAt = startedAt;
    }

    public Instant getExportedAt() {
        return exportedAt;
    }

    public void setExportedAt(Instant exportedAt) {
        this.exportedAt = exportedAt;
    }

    public Instant getFinishedAt() {
        return finishedAt;
    }

    public void setFinishedAt(Instant finishedAt) {
        this.finishedAt = finishedAt;
    }

    public String getManifestDigest() {
        return manifestDigest;
    }

    public void setManifestDigest(String manifestDigest) {
        this.manifestDigest = manifestDigest;
    }

    public String getImageDigest() {
        return imageDigest;
    }

    public void setImageDigest(String imageDigest) {
        this.imageDigest = imageDigest;
    }

    public String getSignerIdentity() {
        return signerIdentity;
    }

    public void setSignerIdentity(String signerIdentity) {
        this.signerIdentity = signerIdentity;
    }

    public String getSignerIssuer() {
        return signerIssuer;
    }

    public void setSignerIssuer(String signerIssuer) {
        this.signerIssuer = signerIssuer;
    }

    public String getSignerKeySha256() {
        return signerKeySha256;
    }

    public void setSignerKeySha256(String signerKeySha256) {
        this.signerKeySha256 = signerKeySha256;
    }

    public String getExportSchemaVersion() {
        return exportSchemaVersion;
    }

    public void setExportSchemaVersion(String exportSchemaVersion) {
        this.exportSchemaVersion = exportSchemaVersion;
    }

    public String getExportSha256() {
        return exportSha256;
    }

    public void setExportSha256(String exportSha256) {
        this.exportSha256 = exportSha256;
    }

    public Long getExportSize() {
        return exportSize;
    }

    public void setExportSize(Long exportSize) {
        this.exportSize = exportSize;
    }

    /**
     * Not on the run's view: the runs are read under the project's rule alone, and the list would name, by id, a
     * target the reader is not shown (decision 0042 §4).
     */
    @JsonIgnore
    public String getExportTargets() {
        return exportTargets;
    }

    public void setExportTargets(String exportTargets) {
        this.exportTargets = exportTargets;
    }

    public Integer getExitCode() {
        return exitCode;
    }

    public void setExitCode(Integer exitCode) {
        this.exitCode = exitCode;
    }

    public Long getOutputSize() {
        return outputSize;
    }

    public void setOutputSize(Long outputSize) {
        this.outputSize = outputSize;
    }

    public String getOutputSha256() {
        return outputSha256;
    }

    public void setOutputSha256(String outputSha256) {
        this.outputSha256 = outputSha256;
    }

    public String getProductVersion() {
        return productVersion;
    }

    public void setProductVersion(String productVersion) {
        this.productVersion = productVersion;
    }

    public String getOutputMediaType() {
        return outputMediaType;
    }

    public void setOutputMediaType(String outputMediaType) {
        this.outputMediaType = outputMediaType;
    }

    public String getSigningKeyId() {
        return signingKeyId;
    }

    public void setSigningKeyId(String signingKeyId) {
        this.signingKeyId = signingKeyId;
    }

    public String getPackageSha256() {
        return packageSha256;
    }

    public void setPackageSha256(String packageSha256) {
        this.packageSha256 = packageSha256;
    }
}
