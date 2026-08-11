import { Column, Entity, PrimaryColumn } from 'typeorm';
import { stringColumn, timestampColumn } from '../columns';

/**
 * Une entrée du journal d'audit.
 *
 * Trois propriétés font qu'un journal vaut la peine d'exister, et la première version
 * n'avait que la première : ce qui s'est passé et qui l'a fait ; d'où ; et **s'il a
 * été modifié**. La troisième est le rôle de `previousHash` / `entryHash`, qui
 * chaînent les entrées (voir `audit-hash.ts`).
 *
 * Cela ne rend pas le journal inaltérable — qui peut écrire dans la table peut
 * réécrire toute la chaîne — mais rend détectable la modification *sélective*, qui est
 * la menace réaliste quand la ligne intéressante est une parmi des milliers.
 *
 * `timestamp` est une **chaîne**, et c'est structurel : il entre dans le hachage, donc
 * la microseconde compte, donc il ne doit jamais transiter par un `Date` (voir
 * `database/pg-types.ts`).
 */
@Entity('audit_logs')
export class AuditLog {
    @PrimaryColumn({ type: 'uuid' })
    id!: string;

    @Column(stringColumn())
    description!: string;

    @Column({ ...stringColumn(), name: 'operation_type' })
    operationType!: string;

    @Column({ ...stringColumn(), name: 'resource_id' })
    resourceId!: string;

    @Column(timestampColumn())
    timestamp!: Date;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'user_id' })
    userId!: string | null;

    @Column({ ...stringColumn(64, { nullable: true }), name: 'ip_address' })
    ipAddress!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'user_agent' })
    userAgent!: string | null;

    /** `null` sur la toute première entrée, et sur celles qui précèdent le chaînage. */
    @Column({ ...stringColumn(64, { nullable: true }), name: 'previous_hash' })
    previousHash!: string | null;

    @Column({ ...stringColumn(64, { nullable: true }), name: 'entry_hash' })
    entryHash!: string | null;
}

/**
 * Les valeurs connues d'`operationType`.
 *
 * Pas une énumération contrainte — la colonne est une chaîne — mais un endroit unique
 * pour éviter les fautes de frappe et la dérive entre les appelants.
 */
export const AuditOperation = {
    LOGIN_SUCCESS: 'LOGIN_SUCCESS',
    LOGIN_FAILURE: 'LOGIN_FAILURE',
    /** Tentative refusée par le limiteur, avant toute vérification de mot de passe. */
    LOGIN_BLOCKED: 'LOGIN_BLOCKED',
    PASSWORD_CHANGED: 'PASSWORD_CHANGED',
    USER_CREATED: 'USER_CREATED',
    USER_UPDATED: 'USER_UPDATED',
    USER_PASSWORD_RESET: 'USER_PASSWORD_RESET',
    USER_DELETED: 'USER_DELETED',
    API_KEY_CREATED: 'API_KEY_CREATED',
    API_KEY_DELETED: 'API_KEY_DELETED',
    SETTING_UPDATED: 'SETTING_UPDATED',
    /** Un triage peut supprimer un constat : c'est une décision de sécurité. */
    ISSUE_TRIAGED: 'ISSUE_TRIAGED',
    SCAN_TRIGGERED: 'SCAN_TRIGGERED',
    TICKET_CREATED: 'TICKET_CREATED',
    GATE_POLICY_UPDATED: 'GATE_POLICY_UPDATED',
    /** Sans quoi un balayage de tous les endpoints ne laisse aucune trace. */
    ACCESS_DENIED: 'ACCESS_DENIED',
    /** Une clé de déploiement a quitté le plan de contrôle (mode délégué). */
    AGENT_CREDENTIAL_SENT: 'AGENT_CREDENTIAL_SENT',
    AGENT_RESULT_SUBMITTED: 'AGENT_RESULT_SUBMITTED',
    AGENT_CREATED: 'AGENT_CREATED',
    AGENT_UPDATED: 'AGENT_UPDATED',
    AGENT_DELETED: 'AGENT_DELETED'
} as const;

export type AuditOperationType = (typeof AuditOperation)[keyof typeof AuditOperation];
