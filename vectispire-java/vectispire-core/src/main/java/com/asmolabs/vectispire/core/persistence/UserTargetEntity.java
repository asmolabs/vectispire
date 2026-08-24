package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * One account's right to see one target.
 *
 * <p>The whole row is its key: there is nothing to record beyond the pairing itself, and a
 * surrogate identifier would let the same pairing be inserted twice — which reads as a
 * duplicate on a screen and as nothing at all in a query.
 */
@Entity
@Table(name = "t_user_target")
public class UserTargetEntity {

    @EmbeddedId
    private Id id;

    public UserTargetEntity() {}

    public UserTargetEntity(Long userId, String targetKind, Long targetId) {
        this.id = new Id(userId, targetKind, targetId);
    }

    /** @param targetKind {@code repository} or {@code container} — see {@code t_user_target} */
    @Embeddable
    public record Id(
            @Column(name = "user_id", nullable = false) Long userId,
            @Column(name = "target_kind", length = 20, nullable = false) String targetKind,
            @Column(name = "target_id", nullable = false) Long targetId)
            implements Serializable {

        private static final long serialVersionUID = 1L;

        public Id {
            Objects.requireNonNull(userId);
            Objects.requireNonNull(targetKind);
            Objects.requireNonNull(targetId);
        }
    }

    public Id getId() {
        return id;
    }

    public void setId(Id id) {
        this.id = id;
    }
}
