import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { stringColumn, timestampColumn } from '../columns';

// Réexportés depuis le domaine : la définition y vit, parce que le vocabulaire des
// rôles est une règle métier et non une colonne.
export { ADMIN_ROLES, VALID_ROLES } from '../../domain/users/roles';

/**
 * Un compte.
 *
 * La table s'appelle `app_user` et non `user` : ce dernier est un **mot réservé de
 * PostgreSQL**, où `FROM user` désigne la fonction courante et non la table. TypeORM
 * échappe les identifiants de lui-même, mais toute requête écrite à la main devait citer
 * `"user"` — et l'oublier produit une erreur que rien dans le code ne laisse prévoir.
 * Le nom hérité du modèle SQLAlchemy n'avait pas de raison de survivre à la reprise du
 * schéma.
 *
 * `password` porte une empreinte **bcrypt**, interopérable entre Python et Node : la
 * table migre telle quelle, sans réinitialisation. Attention à deux détails à
 * l'écriture — la troncature explicite à 72 **octets**, et le coût, que `bcrypt.gensalt()`
 * fixe à 12 en Python ≥ 4.0 alors que `bcryptjs.genSaltSync()` prend 10 par défaut.
 */
@Entity('app_user')
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
    createdAt!: Date;

    @Column({ ...timestampColumn(), name: 'updated_at' })
    updatedAt!: Date;

    /**
     * Posé par le provisionnement initial : le compte doit changer son mot de passe
     * avant d'accéder au reste. C'est ce qui remplace les identifiants par défaut,
     * qui étaient auparavant affichés sur l'écran de connexion.
     */
    @Column({ type: 'boolean', name: 'must_change_password' })
    mustChangePassword!: boolean;
}
