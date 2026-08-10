import { Column, Entity, PrimaryColumn } from 'typeorm';
import { intColumn, stringColumn, timestampColumn } from '../columns';

export const SCOPE_READ = 'read';
export const SCOPE_SCAN = 'scan';
export const SCOPE_EXPORT = 'export';
export const SCOPE_AGENT = 'agent';

export const ALL_SCOPES = [SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT, SCOPE_AGENT] as const;
/** `agent` n'est **jamais** implicite : ce périmètre donne le droit d'exécuter des scans. */
export const DEFAULT_SCOPES = [SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT] as const;

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
@Entity('api_key')
export class ApiKey {
    @PrimaryColumn({ type: 'uuid' })
    id!: string;

    @Column(stringColumn())
    name!: string;

    @Column({ ...stringColumn(), name: 'key_hash' })
    keyHash!: string;

    @Column(stringColumn(16, { nullable: true }))
    prefix!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;

    @Column({ ...timestampColumn({ nullable: true }), name: 'last_used_at' })
    lastUsedAt!: string | null;

    /** Liste séparée par des virgules. */
    @Column(stringColumn())
    scopes!: string;

    @Column({ ...stringColumn(20, { nullable: true }), name: 'target_kind' })
    targetKind!: string | null;

    @Column({ ...intColumn({ nullable: true }), name: 'target_id' })
    targetId!: number | null;

    /** Une clé expirée est traitée comme invalide, mais la ligne est conservée : la
     *  piste d'audit a besoin de savoir qu'elle a existé. */
    @Column({ ...timestampColumn({ nullable: true }), name: 'expires_at' })
    expiresAt!: string | null;
}
