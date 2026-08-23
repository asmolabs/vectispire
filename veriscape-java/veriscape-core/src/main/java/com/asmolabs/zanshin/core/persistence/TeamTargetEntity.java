package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * One team's right to see one target.
 *
 * <p>{@code (target_kind, target_id)} points into one of two tables depending on the kind, so
 * there is no foreign key — the same shape as {@link UserTargetEntity}, documented on the
 * changeset that creates the table.
 */
@Entity
@Table(name = "t_team_target")
public class TeamTargetEntity {

    @EmbeddedId
    private Id id;

    public TeamTargetEntity() {}

    public TeamTargetEntity(Long teamId, String targetKind, Long targetId) {
        this.id = new Id(teamId, targetKind, targetId);
    }

    /** @param targetKind {@code repository} or {@code container} — see {@code t_team_target} */
    @Embeddable
    public record Id(
            @Column(name = "team_id", nullable = false) Long teamId,
            @Column(name = "target_kind", length = 20, nullable = false) String targetKind,
            @Column(name = "target_id", nullable = false) Long targetId)
            implements Serializable {

        private static final long serialVersionUID = 1L;

        public Id {
            Objects.requireNonNull(teamId);
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
