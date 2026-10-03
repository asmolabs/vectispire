package com.asmolabs.vectispire.core.forges.persistence;

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
 * One repository a connection has listed, keyed by the forge's own id (decision 0037 §3) — the snapshot a
 * discovery compares itself with. A metadata column is null when the forge did not give the value: unknown is
 * not zero. Nothing is deleted from here but with the connection; a repository no completed run lists any more
 * is marked gone, and stays.
 */
@Entity
@Table(name = "t_forge_repository")
public class ForgeRepositoryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "connection_id", nullable = false)
    private UUID connectionId;

    @Column(name = "forge_id", length = 64, nullable = false)
    private String forgeId;

    @Column(name = "full_path", length = 1000, nullable = false)
    private String fullPath;

    @Column(name = "namespace_path", length = 1000, nullable = false)
    private String namespacePath;

    /** In a user's own namespace: offered unticked by the selection. */
    @Column(name = "personal", nullable = false)
    private boolean personal;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    @Column(name = "default_branch", length = 255)
    private String defaultBranch;

    @Column(name = "archived")
    private Boolean archived;

    @Column(name = "fork")
    private Boolean fork;

    @Column(name = "visibility", length = 20)
    private String visibility;

    @Column(name = "last_activity_at")
    private Instant lastActivityAt;

    @Column(name = "language", length = 100)
    private String language;

    @Column(name = "size_bytes")
    private Long sizeBytes;

    @Column(name = "http_url", length = 1024)
    private String httpUrl;

    @Column(name = "ssh_url", length = 1024)
    private String sshUrl;

    @Column(name = "web_url", length = 1024)
    private String webUrl;

    @Column(name = "first_seen_by", nullable = false)
    private Long firstSeenBy;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt;

    @Column(name = "last_seen_by", nullable = false)
    private Long lastSeenBy;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    /** The last discovery that saw it renamed, moved, re-branched or (un)archived. */
    @Column(name = "changed_by")
    private Long changedBy;

    @Column(name = "change_summary", length = 1500)
    private String changeSummary;

    /** The completed discovery that no longer listed it; null while listed. */
    @Column(name = "gone_by")
    private Long goneBy;

    @Column(name = "gone_at")
    private Instant goneAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UUID getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(UUID connectionId) {
        this.connectionId = connectionId;
    }

    public String getForgeId() {
        return forgeId;
    }

    public void setForgeId(String forgeId) {
        this.forgeId = forgeId;
    }

    public String getFullPath() {
        return fullPath;
    }

    public void setFullPath(String fullPath) {
        this.fullPath = fullPath;
    }

    public String getNamespacePath() {
        return namespacePath;
    }

    public void setNamespacePath(String namespacePath) {
        this.namespacePath = namespacePath;
    }

    public boolean getPersonal() {
        return personal;
    }

    public void setPersonal(boolean personal) {
        this.personal = personal;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDefaultBranch() {
        return defaultBranch;
    }

    public void setDefaultBranch(String defaultBranch) {
        this.defaultBranch = defaultBranch;
    }

    public Boolean getArchived() {
        return archived;
    }

    public void setArchived(Boolean archived) {
        this.archived = archived;
    }

    public Boolean getFork() {
        return fork;
    }

    public void setFork(Boolean fork) {
        this.fork = fork;
    }

    public String getVisibility() {
        return visibility;
    }

    public void setVisibility(String visibility) {
        this.visibility = visibility;
    }

    public Instant getLastActivityAt() {
        return lastActivityAt;
    }

    public void setLastActivityAt(Instant lastActivityAt) {
        this.lastActivityAt = lastActivityAt;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public Long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(Long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public String getHttpUrl() {
        return httpUrl;
    }

    public void setHttpUrl(String httpUrl) {
        this.httpUrl = httpUrl;
    }

    public String getSshUrl() {
        return sshUrl;
    }

    public void setSshUrl(String sshUrl) {
        this.sshUrl = sshUrl;
    }

    public String getWebUrl() {
        return webUrl;
    }

    public void setWebUrl(String webUrl) {
        this.webUrl = webUrl;
    }

    public Long getFirstSeenBy() {
        return firstSeenBy;
    }

    public void setFirstSeenBy(Long firstSeenBy) {
        this.firstSeenBy = firstSeenBy;
    }

    public Instant getFirstSeenAt() {
        return firstSeenAt;
    }

    public void setFirstSeenAt(Instant firstSeenAt) {
        this.firstSeenAt = firstSeenAt;
    }

    public Long getLastSeenBy() {
        return lastSeenBy;
    }

    public void setLastSeenBy(Long lastSeenBy) {
        this.lastSeenBy = lastSeenBy;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public Long getChangedBy() {
        return changedBy;
    }

    public void setChangedBy(Long changedBy) {
        this.changedBy = changedBy;
    }

    public String getChangeSummary() {
        return changeSummary;
    }

    public void setChangeSummary(String changeSummary) {
        this.changeSummary = changeSummary;
    }

    public Long getGoneBy() {
        return goneBy;
    }

    public void setGoneBy(Long goneBy) {
        this.goneBy = goneBy;
    }

    public Instant getGoneAt() {
        return goneAt;
    }

    public void setGoneAt(Instant goneAt) {
        this.goneAt = goneAt;
    }
}
