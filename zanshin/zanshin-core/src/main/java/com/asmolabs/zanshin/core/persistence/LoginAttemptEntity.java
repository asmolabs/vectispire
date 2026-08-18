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
import java.util.UUID;

/**
 * One failed login, kept only long enough to be counted.
 *
 * <p>Rows rather than an in-memory counter, because the throttle has to hold across instances:
 * counting in one process lets an attacker spread the attempts across the others.
 */
@Entity
@Table(name = "t_login_attempt")
public class LoginAttemptEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "counter_key", length = 255, nullable = false)
    private String counterKey;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getCounterKey() {
        return counterKey;
    }

    public void setCounterKey(String counterKey) {
        this.counterKey = counterKey;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public void setOccurredAt(Instant occurredAt) {
        this.occurredAt = occurredAt;
    }
}
