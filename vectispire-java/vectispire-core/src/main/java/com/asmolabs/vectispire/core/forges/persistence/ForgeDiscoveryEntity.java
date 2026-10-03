package com.asmolabs.vectispire.core.forges.persistence;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
 * One discovery of a forge connection (decision 0037 §3): requested by an administrator, claimed by a
 * control-plane instance under a lease it renews as it lists, and what came of it — its progress while it runs,
 * its comparison with the snapshot once it ends. {@code activeKey} is the connection's id while the run is
 * pending or running and null once it ended: unique, it keeps one discovery per connection at a time. The queue's
 * own columns — the key, the claimant, the lease — are not published.
 */
@Entity
@Table(name = "t_forge_discovery")
public class ForgeDiscoveryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "connection_id", nullable = false)
    private UUID connectionId;

    /** {@code DiscoveryState}'s wire name. */
    @Column(name = "state", length = 20, nullable = false)
    private String state;

    /** {@code DiscoveryReason}'s wire name; null for a run not ended short. */
    @Column(name = "reason", length = 40)
    private String reason;

    @Column(name = "detail", length = 2000)
    private String detail;

    /** The connection's id while pending or running; null once ended. */
    @Column(name = "active_key", length = 36)
    private String activeKey;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt;

    @Column(name = "requested_by", length = 255, nullable = false)
    private String requestedBy;

    @Column(name = "claimed_by", length = 100)
    private String claimedBy;

    @Column(name = "lease_expires_at")
    private Instant leaseExpiresAt;

    /** How many times an instance took it; a lapsed lease past three fails it. */
    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "finished_at")
    private Instant finishedAt;

    @Column(name = "namespaces_seen", nullable = false)
    private int namespacesSeen;

    @Column(name = "repositories_seen", nullable = false)
    private int repositoriesSeen;

    /** Listed, and not kept: an id, a path or a name longer than its column. */
    @Column(name = "repositories_skipped", nullable = false)
    private int repositoriesSkipped;

    @Column(name = "requests_made", nullable = false)
    private int requestsMade;

    @Column(name = "rate_limit_wait_seconds", nullable = false)
    private long rateLimitWaitSeconds;

    /** When the rate limit that ended the run partial lifts. */
    @Column(name = "rate_limit_reset_at")
    private Instant rateLimitResetAt;

    /** Written when the run ends; null before. */
    @Column(name = "new_count")
    private Integer newCount;

    @Column(name = "changed_count")
    private Integer changedCount;

    @Column(name = "gone_count")
    private Integer goneCount;

    /** {@code UnreadableNamespace.encode}'s text: what the run could not read, and why; null when it read everything. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "unreadable_namespaces")
    private String unreadableNamespaces;

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

    @JsonIgnore
    public String getClaimedBy() {
        return claimedBy;
    }

    public void setClaimedBy(String claimedBy) {
        this.claimedBy = claimedBy;
    }

    @JsonIgnore
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

    public Instant getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Instant startedAt) {
        this.startedAt = startedAt;
    }

    public Instant getFinishedAt() {
        return finishedAt;
    }

    public void setFinishedAt(Instant finishedAt) {
        this.finishedAt = finishedAt;
    }

    public int getNamespacesSeen() {
        return namespacesSeen;
    }

    public void setNamespacesSeen(int namespacesSeen) {
        this.namespacesSeen = namespacesSeen;
    }

    public int getRepositoriesSeen() {
        return repositoriesSeen;
    }

    public void setRepositoriesSeen(int repositoriesSeen) {
        this.repositoriesSeen = repositoriesSeen;
    }

    public int getRepositoriesSkipped() {
        return repositoriesSkipped;
    }

    public void setRepositoriesSkipped(int repositoriesSkipped) {
        this.repositoriesSkipped = repositoriesSkipped;
    }

    public int getRequestsMade() {
        return requestsMade;
    }

    public void setRequestsMade(int requestsMade) {
        this.requestsMade = requestsMade;
    }

    public long getRateLimitWaitSeconds() {
        return rateLimitWaitSeconds;
    }

    public void setRateLimitWaitSeconds(long rateLimitWaitSeconds) {
        this.rateLimitWaitSeconds = rateLimitWaitSeconds;
    }

    public Instant getRateLimitResetAt() {
        return rateLimitResetAt;
    }

    public void setRateLimitResetAt(Instant rateLimitResetAt) {
        this.rateLimitResetAt = rateLimitResetAt;
    }

    public Integer getNewCount() {
        return newCount;
    }

    public void setNewCount(Integer newCount) {
        this.newCount = newCount;
    }

    public Integer getChangedCount() {
        return changedCount;
    }

    public void setChangedCount(Integer changedCount) {
        this.changedCount = changedCount;
    }

    public Integer getGoneCount() {
        return goneCount;
    }

    public void setGoneCount(Integer goneCount) {
        this.goneCount = goneCount;
    }

    public String getUnreadableNamespaces() {
        return unreadableNamespaces;
    }

    public void setUnreadableNamespaces(String unreadableNamespaces) {
        this.unreadableNamespaces = unreadableNamespaces;
    }
}
