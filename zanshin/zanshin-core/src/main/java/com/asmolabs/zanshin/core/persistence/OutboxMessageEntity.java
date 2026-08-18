package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import org.springframework.data.domain.Persistable;
import jakarta.persistence.Transient;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostLoad;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A message to send, written in the same transaction as the change that caused it.
 *
 * <p>That is the point of an outbox: a notification cannot be sent for a scan that rolled back,
 * and a scan cannot commit without its notification being queued.
 */
@Entity
@Table(name = "t_outbox_message")
public class OutboxMessageEntity implements Persistable<UUID> {


    /**
     * Assigned, not generated, and therefore {@link Persistable}.
     *
     * <p>The identifier has to exist <em>before</em> the row does: it is stamped into the payload as the message id, which is how a receiver tells a redelivery from a new message.
     *
     * <p>Spring Data decides insert-versus-update from "is the id null", so an assigned id makes
     * every save a merge — which on a row that does not exist yet fails rather than inserting.
     * {@code isNew} answers the question honestly instead.
     */
    @Transient
    private boolean persisted;

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "message_type", length = 50, nullable = false)
    private String messageType;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "payload", nullable = false)
    private String payload;

    @Column(name = "status", length = 20, nullable = false)
    private String status;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "next_attempt_at")
    private Instant nextAttemptAt;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "last_error")
    private String lastError;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "sent_at")
    private Instant sentAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getAttempts() {
        return attempts;
    }

    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }

    public Instant getNextAttemptAt() {
        return nextAttemptAt;
    }

    public void setNextAttemptAt(Instant nextAttemptAt) {
        this.nextAttemptAt = nextAttemptAt;
    }

    public String getLastError() {
        return lastError;
    }

    public void setLastError(String lastError) {
        this.lastError = lastError;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getSentAt() {
        return sentAt;
    }

    public void setSentAt(Instant sentAt) {
        this.sentAt = sentAt;
    }

    @Override
    public boolean isNew() {
        return !persisted;
    }

    /** Both callbacks, so a row read back is never mistaken for one that has yet to be written. */
    @PostLoad
    @PostPersist
    void markPersisted() {
        this.persisted = true;
    }
}
