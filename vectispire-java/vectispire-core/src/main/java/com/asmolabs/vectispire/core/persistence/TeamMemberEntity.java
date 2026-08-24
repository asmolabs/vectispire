package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * One account's membership of one team.
 *
 * <p>The whole row is its key, like {@link UserTargetEntity} and for the same reason: there is
 * nothing to record beyond the pairing, and a surrogate identifier would let it exist twice.
 */
@Entity
@Table(name = "t_team_member")
public class TeamMemberEntity {

    @EmbeddedId
    private Id id;

    public TeamMemberEntity() {}

    public TeamMemberEntity(Long teamId, Long userId) {
        this.id = new Id(teamId, userId);
    }

    @Embeddable
    public record Id(
            @Column(name = "team_id", nullable = false) Long teamId,
            @Column(name = "user_id", nullable = false) Long userId)
            implements Serializable {

        private static final long serialVersionUID = 1L;

        public Id {
            Objects.requireNonNull(teamId);
            Objects.requireNonNull(userId);
        }
    }

    public Id getId() {
        return id;
    }

    public void setId(Id id) {
        this.id = id;
    }
}
