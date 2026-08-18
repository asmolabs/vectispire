package com.asmolabs.zanshin.core.persistence;

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
 * One run of the scanners against one target.
 *
 * <p><b>{@code sbom} and {@code cves} are the raw payloads, and the only purgeable columns.</b>
 * Everything else — the summary, the counts, the findings, the issues — is the durable record,
 * which is why retention drops the blobs and keeps the rest.
 *
 * <p>{@code claimedBy}, {@code claimedAt} and {@code leaseExpiresAt} are the queue: the row is
 * the lock, so a worker that dies releases it by not renewing rather than by holding a lock in
 * a process that no longer exists.
 */
@Entity
@Table(name = "t_scan")
public class ScanEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "branch", length = 255, nullable = false)
    private String branch;

    @Column(name = "sub_path", length = 255)
    private String subPath;

    @Column(name = "status", length = 255, nullable = false)
    private String status;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "sbom")
    private String sbom;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "cves")
    private String cves;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "summary")
    private String summary;

    @Column(name = "duration_ms")
    private Long durationMs;

    @Column(name = "findings_count", nullable = false)
    private int findingsCount;

    @Column(name = "new_issues_count", nullable = false)
    private int newIssuesCount;

    @Column(name = "resolved_issues_count", nullable = false)
    private int resolvedIssuesCount;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "error")
    private String error;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "version", length = 255)
    private String version;

    @Column(name = "project_type", length = 255)
    private String projectType;

    @Column(name = "repo_id")
    private Long repoId;

    @Column(name = "container_id")
    private Long containerId;

    @Column(name = "required_agent_label", length = 255)
    private String requiredAgentLabel;

    @Column(name = "claimed_by", length = 64)
    private String claimedBy;

    @Column(name = "claimed_at")
    private Instant claimedAt;

    @Column(name = "lease_expires_at")
    private Instant leaseExpiresAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getSubPath() {
        return subPath;
    }

    public void setSubPath(String subPath) {
        this.subPath = subPath;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSbom() {
        return sbom;
    }

    public void setSbom(String sbom) {
        this.sbom = sbom;
    }

    public String getCves() {
        return cves;
    }

    public void setCves(String cves) {
        this.cves = cves;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public Long getDurationMs() {
        return durationMs;
    }

    public void setDurationMs(Long durationMs) {
        this.durationMs = durationMs;
    }

    public int getFindingsCount() {
        return findingsCount;
    }

    public void setFindingsCount(int findingsCount) {
        this.findingsCount = findingsCount;
    }

    public int getNewIssuesCount() {
        return newIssuesCount;
    }

    public void setNewIssuesCount(int newIssuesCount) {
        this.newIssuesCount = newIssuesCount;
    }

    public int getResolvedIssuesCount() {
        return resolvedIssuesCount;
    }

    public void setResolvedIssuesCount(int resolvedIssuesCount) {
        this.resolvedIssuesCount = resolvedIssuesCount;
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

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getProjectType() {
        return projectType;
    }

    public void setProjectType(String projectType) {
        this.projectType = projectType;
    }

    public Long getRepoId() {
        return repoId;
    }

    public void setRepoId(Long repoId) {
        this.repoId = repoId;
    }

    public Long getContainerId() {
        return containerId;
    }

    public void setContainerId(Long containerId) {
        this.containerId = containerId;
    }

    public String getRequiredAgentLabel() {
        return requiredAgentLabel;
    }

    public void setRequiredAgentLabel(String requiredAgentLabel) {
        this.requiredAgentLabel = requiredAgentLabel;
    }

    public String getClaimedBy() {
        return claimedBy;
    }

    public void setClaimedBy(String claimedBy) {
        this.claimedBy = claimedBy;
    }

    public Instant getClaimedAt() {
        return claimedAt;
    }

    public void setClaimedAt(Instant claimedAt) {
        this.claimedAt = claimedAt;
    }

    public Instant getLeaseExpiresAt() {
        return leaseExpiresAt;
    }

    public void setLeaseExpiresAt(Instant leaseExpiresAt) {
        this.leaseExpiresAt = leaseExpiresAt;
    }

    public int getAttempts() {
        return attempts;
    }

    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }
}
