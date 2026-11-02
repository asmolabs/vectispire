package com.asmolabs.vectispire.core.access.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One administrator's gesture on one account — created it, reset its password, changed its role — kept so
 * that an approval under four-eyes can ask whether the requester administered the approver (V100).
 *
 * <p>Written in the transaction that applies the gesture, so that an account changed is never an account
 * whose administrator nobody recorded.
 */
@Entity
@Table(name = "t_account_administration")
public class AccountAdministrationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "account_id", nullable = false)
    private Long accountId;

    @Column(name = "administrator_id", nullable = false)
    private Long administratorId;

    /** An {@code AccountGesture}'s wire name. */
    @Column(name = "gesture", length = 32, nullable = false)
    private String gesture;

    /** The role the account held before the gesture. */
    @Column(name = "held_role", length = 32)
    private String heldRole;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    public AccountAdministrationEntity() {}

    public AccountAdministrationEntity(
            Long accountId, Long administratorId, String gesture, String heldRole, Instant occurredAt) {
        this.accountId = accountId;
        this.administratorId = administratorId;
        this.gesture = gesture;
        this.heldRole = heldRole;
        this.occurredAt = occurredAt;
    }

    public String getHeldRole() {
        return heldRole;
    }

    public void setHeldRole(String heldRole) {
        this.heldRole = heldRole;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getAccountId() {
        return accountId;
    }

    public void setAccountId(Long accountId) {
        this.accountId = accountId;
    }

    public Long getAdministratorId() {
        return administratorId;
    }

    public void setAdministratorId(Long administratorId) {
        this.administratorId = administratorId;
    }

    public String getGesture() {
        return gesture;
    }

    public void setGesture(String gesture) {
        this.gesture = gesture;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public void setOccurredAt(Instant occurredAt) {
        this.occurredAt = occurredAt;
    }
}
