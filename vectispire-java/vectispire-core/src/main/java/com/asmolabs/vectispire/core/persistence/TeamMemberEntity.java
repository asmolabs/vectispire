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
 * <p>The pairing is the key, like {@link UserTargetEntity} and for the same reason: a surrogate
 * identifier would let the same membership exist twice.
 *
 * <p><b>{@code origin} is not part of it, and that is the point.</b> A person belongs to a team
 * once, however they came to it; what the column records is which channel is allowed to take the
 * membership away again. Making it part of the key would let the same pairing exist once per
 * channel, which is the duplication the composite key exists to prevent.
 */
@Entity
@Table(name = "t_team_member")
public class TeamMemberEntity {

    @EmbeddedId
    private Id id;

    /**
     * Qui a posé cette ligne, et donc qui peut la retirer.
     *
     * <p>{@code manual} pour une attribution humaine, {@code oidc} pour une revendication de
     * groupe, {@code scim} pour un provisionnement. Chaque canal ne réconcilie que les siennes :
     * une connexion ne doit pas emporter ce qu'un administrateur a décidé, et un annuaire ne doit
     * pas défaire le travail d'un autre.
     */
    @Column(name = "origin", nullable = false, length = 16)
    private String origin = Origin.MANUAL;

    public TeamMemberEntity() {}

    public TeamMemberEntity(Long teamId, Long userId) {
        this(teamId, userId, Origin.MANUAL);
    }

    public TeamMemberEntity(Long teamId, Long userId, String origin) {
        this.id = new Id(teamId, userId);
        this.origin = origin;
    }

    /** Les canaux qui posent une appartenance. */
    public static final class Origin {
        public static final String MANUAL = "manual";
        public static final String OIDC = "oidc";
        public static final String SCIM = "scim";

        private Origin() {}
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
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
