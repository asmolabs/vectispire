import { Column, Entity, PrimaryColumn } from 'typeorm';
import { intColumn, stringColumn, timestampColumn } from '../columns';

/**
 * Une session ouverte.
 *
 * Le jeton **est** la clé primaire : opaque, 32 octets d'entropie, jamais dérivé de
 * l'utilisateur. Pas un JWT — rien à déchiffrer, rien qui périme mal, et la révocation
 * ne demande pas de liste noire, seulement un `DELETE`.
 *
 * En base et non en Redis : c'est ce qui fait survivre les sessions à un redémarrage,
 * et ce qui retire un composant d'infrastructure à un outil qui audite des chaînes
 * d'approvisionnement (migration 0016).
 */
@Entity('session')
export class Session {
    @PrimaryColumn({ type: 'character varying', length: 64 })
    token!: string;

    @Column({ ...intColumn(), name: 'user_id' })
    userId!: number;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;

    /** Rafraîchi à chaque requête : ce qui distingue une session oubliée d'une active. */
    @Column({ ...timestampColumn(), name: 'last_seen_at' })
    lastSeenAt!: string;

    /**
     * L'échéance absolue, calculée à la création. Stockée plutôt que recalculée pour
     * qu'un changement de réglage ne rallonge pas rétroactivement les sessions déjà
     * ouvertes.
     */
    @Column({ ...timestampColumn(), name: 'expires_at' })
    expiresAt!: string;

    /** Pour qu'un utilisateur reconnaisse ses propres sessions et révoque les autres. */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'user_agent' })
    userAgent!: string | null;

    @Column({ ...stringColumn(64, { nullable: true }), name: 'ip_address' })
    ipAddress!: string | null;
}
