package com.asmolabs.vectispire.core.persistence;

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
 * A finding with an identity across scans, and the triage attached to it.
 *
 * <p><b>{@code fingerprint} is the identity.</b> It decides whether what a scan just saw is the
 * same issue as yesterday — with its history, its occurrence count and above all its triage
 * decision — or a new one. Nothing writes it but {@code IssueFingerprint}.
 *
 * <p>{@code firstSeenScanId} and {@code lastSeenScanId} are {@code SET NULL} on delete, unlike
 * the target: an issue outlives the scan that first saw it, which is what "first seen" means.
 */
@Entity
@Table(name = "t_issue")
public class IssueEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "repo_id")
    private Long repoId;

    @Column(name = "container_id")
    private Long containerId;

    @Column(name = "fingerprint", length = 64, nullable = false)
    private String fingerprint;

    @Column(name = "type", length = 50, nullable = false)
    private String type;

    @Column(name = "identifier", length = 255)
    private String identifier;

    @Column(name = "package_name", length = 255)
    private String packageName;

    @Column(name = "package_version", length = 255)
    private String packageVersion;

    @Column(name = "purl", length = 255)
    private String purl;

    @Column(name = "file_path", length = 500)
    private String filePath;

    @Column(name = "source", length = 50)
    private String source;

    @Column(name = "severity", length = 50)
    private String severity;

    @Column(name = "epss_score")
    private Double epssScore;

    @Column(name = "is_kev", nullable = false)
    private boolean isKev;

    @Column(name = "cvss_score")
    private Double cvssScore;

    @Column(name = "cvss_vector", length = 255)
    private String cvssVector;

    @Column(name = "fix_state", length = 50)
    private String fixState;

    @Column(name = "fix_versions", length = 255)
    private String fixVersions;

    @Column(name = "link", length = 500)
    private String link;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "description")
    private String description;

    @Column(name = "reachability", length = 16, nullable = false)
    private String reachability = "UNKNOWN";

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "reachable_symbols")
    private String reachableSymbols;

    @Column(name = "state", length = 20, nullable = false)
    private String state;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "first_seen_scan_id")
    private Long firstSeenScanId;

    @Column(name = "last_seen_scan_id")
    private Long lastSeenScanId;

    @Column(name = "times_seen", nullable = false)
    private int timesSeen;

    @Column(name = "triage_status", length = 30, nullable = false)
    private String triageStatus;

    @Column(name = "triage_justification", length = 64)
    private String triageJustification;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "triage_comment")
    private String triageComment;

    @Column(name = "triaged_by", length = 255)
    private String triagedBy;

    @Column(name = "triaged_at")
    private Instant triagedAt;

    @Column(name = "triage_expires_at")
    private Instant triageExpiresAt;

    @Column(name = "is_direct_dependency")
    private Boolean isDirectDependency;

    @Column(name = "line")
    private Integer line;

    @Column(name = "ticket_ref", length = 64)
    private String ticketRef;

    @Column(name = "ticket_url", length = 500)
    private String ticketUrl;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getPackageVersion() {
        return packageVersion;
    }

    public void setPackageVersion(String packageVersion) {
        this.packageVersion = packageVersion;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Double getEpssScore() {
        return epssScore;
    }

    public void setEpssScore(Double epssScore) {
        this.epssScore = epssScore;
    }

    public boolean getIsKev() {
        return isKev;
    }

    public boolean isKev() {
        return isKev;
    }

    public void setIsKev(boolean isKev) {
        this.isKev = isKev;
    }

    public void setKev(boolean isKev) {
        this.isKev = isKev;
    }

    public Double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(Double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getCvssVector() {
        return cvssVector;
    }

    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector;
    }

    public String getFixState() {
        return fixState;
    }

    public void setFixState(String fixState) {
        this.fixState = fixState;
    }

    public String getFixVersions() {
        return fixVersions;
    }

    public void setFixVersions(String fixVersions) {
        this.fixVersions = fixVersions;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public Instant getFirstSeenAt() {
        return firstSeenAt;
    }

    public void setFirstSeenAt(Instant firstSeenAt) {
        this.firstSeenAt = firstSeenAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(Instant resolvedAt) {
        this.resolvedAt = resolvedAt;
    }

    public Long getFirstSeenScanId() {
        return firstSeenScanId;
    }

    public void setFirstSeenScanId(Long firstSeenScanId) {
        this.firstSeenScanId = firstSeenScanId;
    }

    public Long getLastSeenScanId() {
        return lastSeenScanId;
    }

    public void setLastSeenScanId(Long lastSeenScanId) {
        this.lastSeenScanId = lastSeenScanId;
    }

    public int getTimesSeen() {
        return timesSeen;
    }

    public void setTimesSeen(int timesSeen) {
        this.timesSeen = timesSeen;
    }

    public String getTriageStatus() {
        return triageStatus;
    }

    public void setTriageStatus(String triageStatus) {
        this.triageStatus = triageStatus;
    }

    public String getTriageJustification() {
        return triageJustification;
    }

    public void setTriageJustification(String triageJustification) {
        this.triageJustification = triageJustification;
    }

    public String getTriageComment() {
        return triageComment;
    }

    public void setTriageComment(String triageComment) {
        this.triageComment = triageComment;
    }

    public String getTriagedBy() {
        return triagedBy;
    }

    public void setTriagedBy(String triagedBy) {
        this.triagedBy = triagedBy;
    }

    public Instant getTriagedAt() {
        return triagedAt;
    }

    public void setTriagedAt(Instant triagedAt) {
        this.triagedAt = triagedAt;
    }

    public Instant getTriageExpiresAt() {
        return triageExpiresAt;
    }

    public void setTriageExpiresAt(Instant triageExpiresAt) {
        this.triageExpiresAt = triageExpiresAt;
    }

    public Boolean getIsDirectDependency() {
        return isDirectDependency;
    }

    public void setIsDirectDependency(Boolean isDirectDependency) {
        this.isDirectDependency = isDirectDependency;
    }

    public Integer getLine() {
        return line;
    }

    public void setLine(Integer line) {
        this.line = line;
    }

    public String getTicketRef() {
        return ticketRef;
    }

    public void setTicketRef(String ticketRef) {
        this.ticketRef = ticketRef;
    }

    public String getTicketUrl() {
        return ticketUrl;
    }

    public void setTicketUrl(String ticketUrl) {
        this.ticketUrl = ticketUrl;
    }

    public String getReachability() {
        return reachability;
    }

    public void setReachability(String reachability) {
        this.reachability = reachability != null ? reachability : "UNKNOWN";
    }

    public String getReachableSymbols() {
        return reachableSymbols;
    }

    public void setReachableSymbols(String reachableSymbols) {
        this.reachableSymbols = reachableSymbols;
    }
}
