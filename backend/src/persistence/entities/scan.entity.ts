import { Column, Entity, Index, PrimaryGeneratedColumn, JoinColumn, ManyToOne } from 'typeorm';
import { bigIntColumn, intColumn, jsonColumn, stringColumn, textColumn, timestampColumn } from '../columns';
import { Container } from './container.entity';
import { Repository } from './repository.entity';

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
/**
 * L'index de la file, et **il est structurel, pas une optimisation**.
 *
 * La réclamation cherche `status = 'pending'` puis trie par date. Sans index, MySQL
 * parcourt la table entière et pose un verrou sur chaque ligne examinée — `SKIP LOCKED`
 * saute celles déjà prises, mais les transactions concurrentes finissent par s'attendre et
 * la réclamation échoue sur « Lock wait timeout exceeded ». PostgreSQL tolérait l'absence
 * d'index sur de petites tables, ce qui a laissé le défaut invisible jusqu'à ce qu'un
 * second moteur le nomme.
 *
 * L'ordre des colonnes suit celui de la requête : filtre d'abord, tri ensuite.
 */
@Index('idx_scan_file', ['status', 'createdAt', 'id'])
@Entity('t_scan')
export class Scan {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column(stringColumn())
    branch!: string;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'sub_path' })
    subPath!: string | null;

    @Column(stringColumn())
    status!: string;

    /**
     * L'étiquette d'agent que ce scan exige, ou `null` pour « n'importe lequel ».
     *
     * **Recopiée depuis la cible au moment de la mise en file, et non lue par jointure.**
     * Deux raisons. La réclamation est un `SELECT … FOR UPDATE SKIP LOCKED` sur cette seule
     * table : y ajouter une jointure ferait verrouiller les lignes jointes, ce qui est
     * exactement le genre de détail qui ne se voit qu'en production sous charge. Et un scan
     * en file garde ainsi l'exigence qui valait quand on l'a demandé — changer l'étiquette
     * d'un dépôt ne rerouté pas ce qui attend déjà.
     */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'required_agent_label' })
    requiredAgentLabel!: string | null;

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

    @Column({ ...intColumn({ default: 0 }), name: 'findings_count' })
    findingsCount!: number;

    /**
     * Écart avec le scan précédent de la même cible. Stocké plutôt que dérivé, pour
     * qu'une liste de scans puisse montrer « ce qui a changé » sans ouvrir chaque
     * historique de problème.
     */
    // `default: 0` déclaré ici et non seulement en base : le schéma Alembic le portait,
    // les entités non, et le code marchait par accident du schéma. Un compteur commence à
    // zéro — l'omettre à l'écriture ne doit pas être une erreur.
    @Column({ ...intColumn({ default: 0 }), name: 'new_issues_count' })
    newIssuesCount!: number;

    @Column({ ...intColumn({ default: 0 }), name: 'resolved_issues_count' })
    resolvedIssuesCount!: number;

    /**
     * `text`, et non une colonne courte : un message d'échec est exactement le champ
     * qu'on ne veut pas tronquer.
     */
    @Column(textColumn({ nullable: true }))
    error!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: Date;

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
    claimedAt!: Date | null;

    /**
     * Renouvelé par le worker à mesure qu'il progresse. Un scan dont le bail a expiré
     * n'est pas tué — rien ici ne peut tuer un fil sur une autre machine — il devient
     * *réclamable*, et le worker qui finit par rendre son résultat est refusé.
     */
    @Column({ ...timestampColumn({ nullable: true }), name: 'lease_expires_at' })
    leaseExpiresAt!: Date | null;

    /**
     * Incrémenté à chaque réclamation, pour qu'un scan repris et abandonné en boucle
     * finisse par échouer visiblement au lieu de cycler indéfiniment.
     */
    @Column(intColumn({ default: 0 }))
    attempts!: number;

    /** Déclarée pour la contrainte, pas pour être parcourue : `containerId` reste la valeur
     *  que le code lit. `ON DELETE CASCADE` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => Container, { onDelete: 'CASCADE', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'container_id' })
    containerIdRelation?: Container | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `repoId` reste la valeur
     *  que le code lit. `ON DELETE CASCADE` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => Repository, { onDelete: 'CASCADE', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'repo_id' })
    repoIdRelation?: Repository | null;
}
