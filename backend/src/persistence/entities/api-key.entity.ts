import { Column, Entity, PrimaryColumn, PrimaryGeneratedColumn } from 'typeorm';
import { intColumn, stringColumn, timestampColumn } from '../columns';

// Réexportés depuis le domaine : le vocabulaire des portées est une règle métier, pas
// une colonne, et la règle de couches interdit l'inverse.
export { ALL_SCOPES, DEFAULT_SCOPES, SCOPE_AGENT, SCOPE_EXPORT, SCOPE_READ, SCOPE_SCAN } from '../../domain/api-keys/scopes';
import { DEFAULT_SCOPES } from '../../domain/api-keys/scopes';

/**
 * Une clé d'API.
 *
 * Format `zsk_<43 caractères>`. Seule l'empreinte bcrypt est stockée ; `prefix` garde
 * les douze premiers caractères **en clair**, ce qui n'est pas un secret et permet de
 * ne comparer par bcrypt que les candidats de ce préfixe — sans quoi chaque requête
 * coûterait un bcrypt par clé existante.
 *
 * `targetKind`/`targetId` restreignent une clé à une cible. Une clé restreinte reçoit
 * un **403 et non un 404** sur une autre cible : dire « cela n'existe pas » à qui n'a
 * pas le droit de savoir serait un mensonge utile, mais dire « vous n'y avez pas
 * droit » est ce que l'opérateur a besoin de lire.
 */
@Entity('t_api_key')
export class ApiKey {
    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column(stringColumn())
    name!: string;

    @Column({ ...stringColumn(), name: 'key_hash' })
    keyHash!: string;

    @Column(stringColumn(16, { nullable: true }))
    prefix!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: Date;

    @Column({ ...timestampColumn({ nullable: true }), name: 'last_used_at' })
    lastUsedAt!: Date | null;

    /** Liste séparée par des virgules. Le défaut n'accorde pas « agent » : ce périmètre
     *  donne le droit d'exécuter des scans et ne doit jamais être implicite. */
    @Column(stringColumn(255, { default: DEFAULT_SCOPES.join(',') }))
    scopes!: string;

    @Column({ ...stringColumn(20, { nullable: true }), name: 'target_kind' })
    targetKind!: string | null;

    @Column({ ...intColumn({ nullable: true }), name: 'target_id' })
    targetId!: number | null;

    /** Une clé expirée est traitée comme invalide, mais la ligne est conservée : la
     *  piste d'audit a besoin de savoir qu'elle a existé. */
    @Column({ ...timestampColumn({ nullable: true }), name: 'expires_at' })
    expiresAt!: Date | null;
}
