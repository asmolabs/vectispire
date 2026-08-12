import { Column, Entity, PrimaryColumn, PrimaryGeneratedColumn, JoinColumn, ManyToOne } from 'typeorm';
import { boolColumn, intColumn, jsonColumn, stringColumn, timestampColumn, uuidColumn } from '../columns';
import { ApiKey } from './api-key.entity';

/** L'agent intégré au processus qui sert l'interface. */
export const KIND_BUILTIN = 'builtin';
export const KIND_REMOTE = 'remote';

/** L'agent utilise ses propres accès git. C'est le défaut, et la recommandation. */
export const CREDENTIALS_LOCAL = 'local';
/** Le plan de contrôle lui envoie une clé de déploiement par tâche. */
export const CREDENTIALS_DELEGATED = 'delegated';

/** Au-delà, un agent est considéré hors ligne. */
export const ONLINE_TTL_SECONDS = 120;

/**
 * Un worker autorisé à exécuter des scans.
 *
 * L'agent intégré est une ligne comme les autres, rafraîchie à chaque tick : un
 * opérateur qui regarde l'écran Agents d'un système calme ne doit pas voir hors ligne
 * le processus même qui lui sert la page.
 *
 * Le mode `delegated` fait sortir une clé de déploiement du plan de contrôle, ce qui
 * est audité à chaque envoi — condition d'existence du mode. Il est en outre refusé
 * sur un transport non chiffré.
 */
@Entity('t_agent')
export class Agent {
    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column(stringColumn())
    name!: string;

    @Column(stringColumn(500, { nullable: true }))
    description!: string | null;

    @Column(stringColumn(20))
    kind!: string;

    /** Étiquettes séparées par des virgules, pour router un scan vers un agent capable. */
    @Column(stringColumn(255, { nullable: true }))
    labels!: string | null;

    @Column({ ...stringColumn(20), name: 'credentials_mode' })
    credentialsMode!: string;

    @Column(boolColumn())
    enabled!: boolean;

    @Column({ ...intColumn({ nullable: true }), name: 'max_concurrent' })
    maxConcurrent!: number | null;

    @Column({ ...uuidColumn({ nullable: true }), name: 'api_key_id' })
    apiKeyId!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    hostname!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    platform!: string | null;

    @Column(stringColumn(50, { nullable: true }))
    version!: string | null;

    @Column({ ...stringColumn(50, { nullable: true }), name: 'scanner_engine' })
    scannerEngine!: string | null;

    @Column(jsonColumn({ nullable: true }))
    capabilities!: unknown;

    /** Comparée à l'enregistrement : un désaccord rend un 409 nommant les deux
     *  versions, plutôt qu'un échec plus tard et plus profond sur un champ manquant. */
    @Column({ ...stringColumn(20, { nullable: true }), name: 'contract_version' })
    contractVersion!: string | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'last_seen_at' })
    lastSeenAt!: Date | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: Date;

    /** Déclarée pour la contrainte, pas pour être parcourue : `apiKeyId` reste la valeur
     *  que le code lit. `ON DELETE SET NULL` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => ApiKey, { onDelete: 'SET NULL', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'api_key_id' })
    apiKeyIdRelation?: ApiKey | null;
}
