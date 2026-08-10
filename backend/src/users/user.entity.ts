import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { stringColumn, timestampColumn } from '../database/columns';

/** Les rôles auxquels l'administration est réservée. */
export const ADMIN_ROLES = ['SUPERUSER', 'ADMIN'] as const;
export const VALID_ROLES = ['SUPERUSER', 'ADMIN', 'USER'] as const;

/**
 * Un compte.
 *
 * La table s'appelle `user`, qui est un **mot réservé de PostgreSQL** : `FROM user`
 * y désigne la fonction courante et non la table. C'est l'un des défauts de
 * portabilité que la suite multi-backends a trouvés côté Python, et il ne se voit ni
 * sur SQLite ni à la lecture. TypeORM échappe les identifiants de lui-même, mais
 * toute requête écrite à la main dans ce projet doit citer `"user"`.
 *
 * `password` porte une empreinte **bcrypt**, interopérable entre Python et Node : la
 * table migre telle quelle, sans réinitialisation. Attention à deux détails à
 * l'écriture — la troncature explicite à 72 **octets**, et le coût, que `bcrypt.gensalt()`
 * fixe à 12 en Python ≥ 4.0 alors que `bcryptjs.genSaltSync()` prend 10 par défaut.
 */
@Entity('user')
export class User {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column(stringColumn(255, { unique: true }))
    username!: string;

    @Column(stringColumn(255, { unique: true, nullable: true }))
    email!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    password!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'display_name' })
    displayName!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'avatar_url' })
    avatarUrl!: string | null;

    @Column(stringColumn())
    role!: string;

    @Column({ type: 'boolean', name: 'is_active' })
    isActive!: boolean;

    @Column({ ...stringColumn(255, { unique: true, nullable: true }), name: 'github_id' })
    githubId!: string | null;

    @Column({ ...stringColumn(255, { unique: true, nullable: true }), name: 'keycloak_id' })
    keycloakId!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;

    @Column({ ...timestampColumn(), name: 'updated_at' })
    updatedAt!: string;

    /**
     * Posé par le provisionnement initial : le compte doit changer son mot de passe
     * avant d'accéder au reste. C'est ce qui remplace les identifiants par défaut,
     * qui étaient auparavant affichés sur l'écran de connexion.
     */
    @Column({ type: 'boolean', name: 'must_change_password' })
    mustChangePassword!: boolean;
}
