package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A session, which is what makes logging out possible.
 *
 * <p><b>The primary key is the token's hash, never the token.</b> A session is looked up by it
 * on every request, so an indirection through a surrogate id would buy nothing — but storing the
 * token itself would mean that every copy of this table is a set of live credentials: a nightly
 * backup, a read replica, a support engineer's {@code select *}, or the audit log's own database
 * being dumped. The hash is a verifier: presenting it does not authenticate, because the lookup
 * hashes what the caller sent. See {@link com.asmolabs.vectispire.common.domain.auth.Sessions#issue()}.
 *
 * <p>The field is named {@code tokenHash} rather than {@code token} on purpose: the two are one
 * assignment apart, and the mistake — writing the clear token into the hash column — produces a
 * system that works perfectly and protects nothing. A wrong name here would make that mistake
 * invisible; this one makes it read wrong.
 *
 * <p>Deleting the row really does log the user out, including from another device.
 */
@Entity
@Table(name = "t_session")
public class SessionEntity {

    @Id
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
