package com.asmolabs.vectispire.core.access.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * An account change filed under four-eyes, waiting for a second administrator or decided by one (V100).
 *
 * <p>{@code passwordHash} is the hash of the temporary password the requester typed: the approval sets it
 * as typed without anybody else seeing it, and the account must change it at its next sign-in. The view
 * of a request never carries it.
 */
@Entity
@Table(name = "t_account_request")
public class AccountRequestEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    /** {@code create} or {@code change}. */
    @Column(name = "kind", length = 16, nullable = false)
    private String kind;

    /** {@code pending}, {@code approved} or {@code rejected}. */
    @Column(name = "status", length = 16, nullable = false)
    private String status;

    /** The account a change is about; null for a creation, until it is approved. */
    @Column(name = "account_id")
    private Long accountId;

    @Column(name = "username", length = 255, nullable = false)
    private String username;

    @Column(name = "email", length = 255)
    private String email;

    @Column(name = "display_name", length = 255)
    private String displayName;

    /** The role the account held when the change was filed; null for a creation. */
    @Column(name = "held_role", length = 32)
    private String heldRole;

    /** The role asked for; null for a change that keeps the role. */
    @Column(name = "requested_role", length = 32)
    private String requestedRole;

    @Column(name = "password_hash", length = 255)
    private String passwordHash;

    @Column(name = "requested_by_id", nullable = false)
    private Long requestedById;

    @Column(name = "requested_by", length = 255, nullable = false)
    private String requestedBy;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt;

    @Column(name = "decided_by", length = 255)
    private String decidedBy;

    @Column(name = "decided_at")
    private Instant decidedAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Long getAccountId() {
        return accountId;
    }

    public void setAccountId(Long accountId) {
        this.accountId = accountId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getHeldRole() {
        return heldRole;
    }

    public void setHeldRole(String heldRole) {
        this.heldRole = heldRole;
    }

    public String getRequestedRole() {
        return requestedRole;
    }

    public void setRequestedRole(String requestedRole) {
        this.requestedRole = requestedRole;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Long getRequestedById() {
        return requestedById;
    }

    public void setRequestedById(Long requestedById) {
        this.requestedById = requestedById;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public void setRequestedBy(String requestedBy) {
        this.requestedBy = requestedBy;
    }

    public Instant getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(Instant requestedAt) {
        this.requestedAt = requestedAt;
    }

    public String getDecidedBy() {
        return decidedBy;
    }

    public void setDecidedBy(String decidedBy) {
        this.decidedBy = decidedBy;
    }

    public Instant getDecidedAt() {
        return decidedAt;
    }

    public void setDecidedAt(Instant decidedAt) {
        this.decidedAt = decidedAt;
    }
}
