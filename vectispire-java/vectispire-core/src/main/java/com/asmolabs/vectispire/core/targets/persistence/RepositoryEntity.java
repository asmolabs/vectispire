package com.asmolabs.vectispire.core.targets.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A monitored repository.
 *
 * <p>{@code requiredAgentLabel} is what routes its scans. Absent means any agent may take
 * them, which is the previous behaviour and the one imposing otherwise retroactively would
 * break.
 */
@Entity
@Table(name = "t_repository")
public class RepositoryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "url", length = 255, nullable = false)
    private String url;

    @Column(name = "branch", length = 255, nullable = false)
    private String branch;

    @Column(name = "sub_path", length = 255)
    private String subPath;

    @Column(name = "name", length = 255)
    private String name;

    @Column(name = "scan_interval_minutes")
    private Integer scanIntervalMinutes;

    @Column(name = "scan_cron", length = 255)
    private String scanCron;

    @Column(name = "required_agent_label", length = 255)
    private String requiredAgentLabel;

    @Column(name = "last_scheduled_scan_at")
    private Instant lastScheduledScanAt;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "ssh_key_id")
    private UUID sshKeyId;

    /** The HTTPS token this repository clones with — never set together with {@link #sshKeyId}. */
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "https_token_id")
    private UUID httpsTokenId;

    /**
     * The opaque name a published badge is served under, or null when none is published.
     *
     * <p><b>Not the id, and that is the point.</b> The badge route is anonymous by necessity — a
     * README is read by a browser with no session — so whatever names the repository in that URL
     * is readable by everyone. A sequential id turns that into an enumeration of the whole
     * estate's posture; a random token names one repository somebody chose to publish.
     */
    @Column(name = "badge_token", length = 64)
    private String badgeToken;

    @Column(name = "tier", length = 32, nullable = false)
    private String tier = "TIER_2_BUSINESS_OPERATIONAL";

    /**
     * Whether this repository belongs to the certified scope of the management system.
     *
     * <p>False by default, and deliberately not "everything is in scope until somebody says
     * otherwise": a scope nobody has drawn is not the whole estate, it is an undrawn scope, and
     * defaulting to true would report a coverage figure the organisation never claimed.
     */
    @Column(name = "in_certified_scope", nullable = false)
    private boolean inCertifiedScope;

    /**
     * The project this repository is filed in, or null for "no project" (decision 0023).
     *
     * <p><b>Read-only to Hibernate, and that is the point.</b> Which project a repository is in
     * decides who sees it, so the column is written by the targeted updates in
     * {@code GitRepositories} and by nothing else. Mapped writable, every save of this entity —
     * the settings form, the badge publication — would write back whatever project the row held
     * when it was read, and a repository moved in another tab would silently move back, taking
     * its visibility with it.
     */
    @Column(name = "project_id", insertable = false, updatable = false)
    private Long projectId;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getScanIntervalMinutes() {
        return scanIntervalMinutes;
    }

    public void setScanIntervalMinutes(Integer scanIntervalMinutes) {
        this.scanIntervalMinutes = scanIntervalMinutes;
    }

    public String getScanCron() {
        return scanCron;
    }

    public void setScanCron(String scanCron) {
        this.scanCron = scanCron;
    }

    public String getRequiredAgentLabel() {
        return requiredAgentLabel;
    }

    public void setRequiredAgentLabel(String requiredAgentLabel) {
        this.requiredAgentLabel = requiredAgentLabel;
    }

    public Instant getLastScheduledScanAt() {
        return lastScheduledScanAt;
    }

    public void setLastScheduledScanAt(Instant lastScheduledScanAt) {
        this.lastScheduledScanAt = lastScheduledScanAt;
    }

    public UUID getSshKeyId() {
        return sshKeyId;
    }

    public void setSshKeyId(UUID sshKeyId) {
        this.sshKeyId = sshKeyId;
    }

    public UUID getHttpsTokenId() {
        return httpsTokenId;
    }

    public void setHttpsTokenId(UUID httpsTokenId) {
        this.httpsTokenId = httpsTokenId;
    }

    public String getTier() {
        return tier;
    }

    public void setTier(String tier) {
        this.tier = tier != null ? tier : "TIER_2_BUSINESS_OPERATIONAL";
    }

    public String getBadgeToken() {
        return badgeToken;
    }

    public void setBadgeToken(String badgeToken) {
        this.badgeToken = badgeToken;
    }

    public boolean isInCertifiedScope() {
        return inCertifiedScope;
    }

    public void setInCertifiedScope(boolean inCertifiedScope) {
        this.inCertifiedScope = inCertifiedScope;
    }

    /** No setter: see the field. */
    public Long getProjectId() {
        return projectId;
    }
}
