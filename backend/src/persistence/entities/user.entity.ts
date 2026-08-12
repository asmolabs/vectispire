import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { stringColumn, timestampColumn } from '../columns';

// Réexportés depuis le domaine : la définition y vit, parce que le vocabulaire des
// rôles est une règle métier et non une colonne.
export { ADMIN_ROLES, VALID_ROLES } from '../../domain/users/roles';

/**
 * Un compte.
 *
 * La table s'appelle `t_user`. Toutes les tables du schéma portent le préfixe `t_`, ce
 * qui écarte d'un coup les collisions avec les mots réservés — `user` en est un en
 * PostgreSQL, où `FROM user` désigne la fonction courante et non la table, mais
 * `session`, `order` ou `group` le sont ailleurs et le problème se serait reposé.
 * Préfixer est plus sûr que renommer au cas par cas : on ne peut pas oublier de le
 * faire pour une table qu'on ajoutera dans deux ans.
 *
 * `password` porte une empreinte **bcrypt**, interopérable entre Python et Node : la
 * table migre telle quelle, sans réinitialisation. Attention à deux détails à
 * l'écriture — la troncature explicite à 72 **octets**, et le coût, que `bcrypt.gensalt()`
 * fixe à 12 en Python ≥ 4.0 alors que `bcryptjs.genSaltSync()` prend 10 par défaut.
 */
@Entity('t_user')
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
