import { Column, Entity, PrimaryColumn, JoinColumn, ManyToOne } from 'typeorm';
import { intColumn, stringColumn, timestampColumn } from '../columns';
import { User } from './user.entity';

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
@Entity('t_session')
export class Session {
    @PrimaryColumn({ type: 'character varying', length: 64 })
    token!: string;

    @Column({ ...intColumn(), name: 'user_id' })
    userId!: number;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: Date;

    /** Rafraîchi à chaque requête : ce qui distingue une session oubliée d'une active. */
    @Column({ ...timestampColumn(), name: 'last_seen_at' })
    lastSeenAt!: Date;

    /**
     * L'échéance absolue, calculée à la création. Stockée plutôt que recalculée pour
     * qu'un changement de réglage ne rallonge pas rétroactivement les sessions déjà
     * ouvertes.
     */
    @Column({ ...timestampColumn(), name: 'expires_at' })
    expiresAt!: Date;

    /** Pour qu'un utilisateur reconnaisse ses propres sessions et révoque les autres. */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'user_agent' })
    userAgent!: string | null;

    @Column({ ...stringColumn(64, { nullable: true }), name: 'ip_address' })
    ipAddress!: string | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `userId` reste la valeur
     *  que le code lit. `ON DELETE CASCADE` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => User, { onDelete: 'CASCADE', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'user_id' })
    userIdRelation?: User | null;
}
