import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { bigIntColumn, intColumn, jsonColumn, stringColumn, textColumn, timestampColumn } from '../columns';

/** En file d'attente. */
export const STATUS_QUEUED = 'pending';
/** Réclamé et en cours. */
export const STATUS_RUNNING = 'scanning';
export const STATUS_COMPLETED = 'completed';
export const STATUS_FAILED = 'failed';

/**
 * Une exécution de scan.
 *
 * `status` dit qu'un scan tourne ; les quatre colonnes de bail disent **qui** le fait
 * tourner et jusqu'à quand. Sans elles, « en cours » signifiait « un fil, quelque part,
 * peut-être » : la reprise au démarrage devait supposer orphelin tout scan en vol et le
 * faire échouer, ce qui est correct pour un processus et détruit le travail d'un autre
 * agent dès qu'il y en a deux.
 *
 * `claimedBy` porte un identifiant de worker (l'uuid de l'agent en hexadécimal), pas
 * une clé étrangère : `agent.id` est un uuid, et une jointure demanderait une
 * conversion qui se comporte différemment sur chaque moteur. Un scan garde ainsi sa
 * provenance même si la ligne d'agent est supprimée plus tard — la propriété la plus
 * utile pour une piste d'audit.
 */
@Entity('scan')
export class Scan {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column(stringColumn())
    branch!: string;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'sub_path' })
    subPath!: string | null;

    @Column(stringColumn())
    status!: string;

    /** Sortie brute des scanners, conservée pour l'audit et purgée par la rétention. */
    @Column(jsonColumn({ nullable: true }))
    sbom!: unknown;

    @Column(jsonColumn({ nullable: true }))
    cves!: unknown;

    @Column(jsonColumn({ nullable: true }))
    summary!: unknown;

    /**
     * La seule colonne du schéma qui a légitimement besoin d'un `bigint` : une durée.
     * Rendue en **chaîne** par le pilote, qui ne suppose pas qu'elle tient dans un
     * `number` — ne pas « corriger » cela.
     */
    @Column({ ...bigIntColumn({ nullable: true }), name: 'duration_ms' })
    durationMs!: string | null;

    @Column({ ...intColumn(), name: 'findings_count' })
    findingsCount!: number;

    /**
     * Écart avec le scan précédent de la même cible. Stocké plutôt que dérivé, pour
     * qu'une liste de scans puisse montrer « ce qui a changé » sans ouvrir chaque
     * historique de problème.
     */
    @Column({ ...intColumn(), name: 'new_issues_count' })
    newIssuesCount!: number;

    @Column({ ...intColumn(), name: 'resolved_issues_count' })
    resolvedIssuesCount!: number;

    /**
     * `text`, et non une colonne courte : un message d'échec est exactement le champ
     * qu'on ne veut pas tronquer.
     */
    @Column(textColumn({ nullable: true }))
    error!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;

    @Column(stringColumn(255, { nullable: true }))
    version!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'project_type' })
    projectType!: string | null;

    @Column({ ...intColumn({ nullable: true }), name: 'repo_id' })
    repoId!: number | null;

    @Column({ ...intColumn({ nullable: true }), name: 'container_id' })
    containerId!: number | null;

    @Column({ ...stringColumn(64, { nullable: true }), name: 'claimed_by' })
    claimedBy!: string | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'claimed_at' })
    claimedAt!: string | null;

    /**
     * Renouvelé par le worker à mesure qu'il progresse. Un scan dont le bail a expiré
     * n'est pas tué — rien ici ne peut tuer un fil sur une autre machine — il devient
     * *réclamable*, et le worker qui finit par rendre son résultat est refusé.
     */
    @Column({ ...timestampColumn({ nullable: true }), name: 'lease_expires_at' })
    leaseExpiresAt!: string | null;

    /**
     * Incrémenté à chaque réclamation, pour qu'un scan repris et abandonné en boucle
     * finisse par échouer visiblement au lieu de cycler indéfiniment.
     */
    @Column(intColumn())
    attempts!: number;
}
