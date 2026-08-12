import { Column, Entity, PrimaryGeneratedColumn, JoinColumn, ManyToOne } from 'typeorm';
import { boolColumn, floatColumn, intColumn, stringColumn, textColumn, timestampColumn } from '../columns';
import { Container } from './container.entity';
import { Repository } from './repository.entity';
import { Scan } from './scan.entity';

export const STATE_OPEN = 'open';
export const STATE_RESOLVED = 'resolved';

/** Le vocabulaire de triage, qui est celui d'OpenVEX à un mot près. */
export const TRIAGE_UNDER_REVIEW = 'under_review';
export const TRIAGE_AFFECTED = 'affected';
export const TRIAGE_NOT_AFFECTED = 'not_affected';
export const TRIAGE_FIXED = 'fixed';

/**
 * Un problème : l'identité d'un constat **à travers les scans**.
 *
 * C'est la table qui porte tout ce qu'un humain a produit — la décision de triage, sa
 * justification VEX, son échéance de réexamen, la référence du ticket ouvert. Les
 * constats bruts, eux, sont jetables : ils appartiennent à une exécution.
 *
 * Le lien entre les deux est `fingerprint`, unique et indexée. Sa formule vit dans
 * `domain/issues/issue-fingerprint.ts` — pas ici, parce qu'elle n'a besoin d'aucune
 * base pour être calculée, et parce qu'une divergence d'un octet résoudrait tout le
 * backlog et le recréerait à neuf, triage perdu.
 *
 * `repoId` et `containerId` sont exclusifs : un problème appartient à une cible.
 */
@Entity('issue')
export class Issue {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column({ ...intColumn({ nullable: true }), name: 'repo_id' })
    repoId!: number | null;

    @Column({ ...intColumn({ nullable: true }), name: 'container_id' })
    containerId!: number | null;

    @Column(stringColumn(64))
    fingerprint!: string;

    @Column(stringColumn(50))
    type!: string;

    @Column(stringColumn(255, { nullable: true }))
    identifier!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'package_name' })
    packageName!: string | null;

    /** Hors de l'empreinte, délibérément : une dépendance obsolète qui le reste à
     *  travers trois montées de version est un problème avec un historique, pas trois. */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'package_version' })
    packageVersion!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    purl!: string | null;

    @Column({ ...stringColumn(500, { nullable: true }), name: 'file_path' })
    filePath!: string | null;

    @Column(stringColumn(50, { nullable: true }))
    source!: string | null;

    @Column(stringColumn(50, { nullable: true }))
    severity!: string | null;

    @Column({ ...floatColumn({ nullable: true }), name: 'epss_score' })
    epssScore!: number | null;

    /** Catalogue CISA KEV. Une « moyenne » exploitée dans la nature l'emporte sur une
     *  « critique » qui ne l'a jamais été, d'où une règle de gate à part entière. */
    @Column({ ...boolColumn({ default: false }), name: 'is_kev' })
    isKev!: boolean;

    @Column({ ...floatColumn({ nullable: true }), name: 'cvss_score' })
    cvssScore!: number | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'cvss_vector' })
    cvssVector!: string | null;

    @Column({ ...stringColumn(50, { nullable: true }), name: 'fix_state' })
    fixState!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'fix_versions' })
    fixVersions!: string | null;

    @Column(stringColumn(500, { nullable: true }))
    link!: string | null;

    @Column(textColumn({ nullable: true }))
    description!: string | null;

    // --- Cycle de vie ---

    @Column(stringColumn(20, { default: STATE_OPEN }))
    state!: string;

    @Column({ ...timestampColumn(), name: 'first_seen_at' })
    firstSeenAt!: Date;

    @Column({ ...timestampColumn(), name: 'last_seen_at' })
    lastSeenAt!: Date;

    @Column({ ...timestampColumn({ nullable: true }), name: 'resolved_at' })
    resolvedAt!: Date | null;

    @Column({ ...intColumn({ nullable: true }), name: 'first_seen_scan_id' })
    firstSeenScanId!: number | null;

    @Column({ ...intColumn({ nullable: true }), name: 'last_seen_scan_id' })
    lastSeenScanId!: number | null;

    // Un problème vu pour la première fois l'a été une fois. Le schéma le disait,
    // l'entité non — et le code marchait par accident du schéma.
    @Column({ ...intColumn({ default: 1 }), name: 'times_seen' })
    timesSeen!: number;

    // --- Triage ---

    @Column({ ...stringColumn(30, { default: TRIAGE_UNDER_REVIEW }), name: 'triage_status' })
    triageStatus!: string;

    /** Exigée par la spécification VEX pour `not_affected`, et garantie présente à
     *  l'écriture par le service de triage. */
    @Column({ ...stringColumn(64, { nullable: true }), name: 'triage_justification' })
    triageJustification!: string | null;

    @Column({ ...textColumn({ nullable: true }), name: 'triage_comment' })
    triageComment!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'triaged_by' })
    triagedBy!: string | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'triaged_at' })
    triagedAt!: Date | null;

    /**
     * Une suppression est un énoncé sur un contexte — « ce chemin de code n'est pas
     * atteignable », « ce paquet n'est pas livré en production ». Les contextes
     * changent, et rien ne ramenait la décision en révision : un `not_affected` posé en
     * janvier restait autoritaire en décembre, dans l'export remis à un client autant
     * que sur le tableau de bord. C'est ainsi que pourrissent les suppressions VEX.
     */
    @Column({ ...timestampColumn({ nullable: true }), name: 'triage_expires_at' })
    triageExpiresAt!: Date | null;

    @Column({ ...boolColumn({ nullable: true }), name: 'is_direct_dependency' })
    isDirectDependency!: boolean | null;

    @Column(intColumn({ nullable: true }))
    line!: number | null;

    // --- Suivi externe ---

    @Column({ ...stringColumn(64, { nullable: true }), name: 'ticket_ref' })
    ticketRef!: string | null;

    @Column({ ...stringColumn(500, { nullable: true }), name: 'ticket_url' })
    ticketUrl!: string | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `containerId` reste la valeur
     *  que le code lit. `ON DELETE CASCADE` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => Container, { onDelete: 'CASCADE', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'container_id' })
    containerIdRelation?: Container | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `firstSeenScanId` reste la valeur
     *  que le code lit. `ON DELETE SET NULL` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => Scan, { onDelete: 'SET NULL', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'first_seen_scan_id' })
    firstSeenScanIdRelation?: Scan | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `lastSeenScanId` reste la valeur
     *  que le code lit. `ON DELETE SET NULL` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => Scan, { onDelete: 'SET NULL', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'last_seen_scan_id' })
    lastSeenScanIdRelation?: Scan | null;

    /** Déclarée pour la contrainte, pas pour être parcourue : `repoId` reste la valeur
     *  que le code lit. `ON DELETE CASCADE` — la règle vivait dans le schéma Alembic et
     *  n'était écrite nulle part dans le modèle. */
    @ManyToOne(() => Repository, { onDelete: 'CASCADE', createForeignKeyConstraints: true })
    @JoinColumn({ name: 'repo_id' })
    repoIdRelation?: Repository | null;
}
