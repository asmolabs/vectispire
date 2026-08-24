package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Which instance currently holds a named responsibility.
 *
 * <p>The lease is a row rather than a lock so it survives the process that took it: an instance
 * that dies stops renewing, the lease lapses, and another takes over. A JVM lock would have
 * been held by a process that no longer exists.
 */
@Entity
@Table(name = "t_leader_lease")
public class LeaderLeaseEntity {

    @Id
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "holder", length = 64)
    private String holder;

    @Column(name = "acquired_at")
    private Instant acquiredAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getHolder() {
        return holder;
    }

    public void setHolder(String holder) {
        this.holder = holder;
    }

    public Instant getAcquiredAt() {
        return acquiredAt;
    }

    public void setAcquiredAt(Instant acquiredAt) {
        this.acquiredAt = acquiredAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
