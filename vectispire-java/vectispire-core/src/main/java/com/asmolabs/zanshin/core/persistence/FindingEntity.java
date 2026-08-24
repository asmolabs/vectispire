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
 * What one scan saw, before it was matched to an issue.
 *
 * <p>Kept alongside the issues rather than folded into them: the issue is the durable identity,
 * the finding is the observation, and "which scan reported this, exactly" is a question audits
 * ask.
 */
@Entity
@Table(name = "t_finding")
public class FindingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "type", length = 50, nullable = false)
    private String type;

    @Column(name = "severity", length = 50)
    private String severity;

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

    @Column(name = "source", length = 50, nullable = false)
    private String source;

    @Column(name = "epss_score")
    private Double epssScore;

    @Column(name = "is_kev", nullable = false)
    private boolean isKev;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

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

    @Column(name = "issue_id")
    private Long issueId;

    @Column(name = "is_direct_dependency")
    private Boolean isDirectDependency;

    @Column(name = "line")
    private Integer line;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "description")
    private String description;

    @Column(name = "reachability", length = 16, nullable = false)
    private String reachability = "UNKNOWN";

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "reachable_symbols")
    private String reachableSymbols;

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

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
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

    public Double getEpssScore() {
        return epssScore;
    }

    public void setEpssScore(Double epssScore) {
        this.epssScore = epssScore;
    }

    public boolean getIsKev() {
        return isKev;
    }

    public void setIsKev(boolean isKev) {
        this.isKev = isKev;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
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

    public Long getIssueId() {
        return issueId;
    }

    public void setIssueId(Long issueId) {
        this.issueId = issueId;
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
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
