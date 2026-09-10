package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A sign-in that has passed the password and is waiting for the six-digit code.
 *
 * <p><b>A row rather than a map entry, so a second instance can answer.</b> This lived in a
 * {@code ConcurrentHashMap} on {@code AuthController}, which made multi-factor sign-in the one
 * feature that a documented, supported deployment quietly broke: the password is exchanged on
 * one instance, the code arrives on another, and the second has never heard of the token. The
 * user is told the challenge expired, a second after it was created.
 *
 * <p><b>The primary key is the token's hash, never the token</b>, for the same reason
 * {@link SessionEntity} is: a challenge token is a credential for the next five minutes, and a
 * table full of them is a set of half-finished sign-ins waiting in every backup. Presenting the
 * stored value does not work, because the lookup hashes what the caller sent.
 *
 * <p>{@code attempts} is counted here and not on the account. The challenge is what the attacker
 * holds and what gets destroyed on the third wrong code; counting on the account would let a
 * wrong guess lock out the legitimate user, which turns a second factor into a denial of service.
 */
@Entity
@Table(name = "t_mfa_challenge")
public class MfaChallengeEntity {

    @Id
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

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

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public int getAttempts() {
        return attempts;
    }

    public void setAttempts(int attempts) {
        this.attempts = attempts;
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
