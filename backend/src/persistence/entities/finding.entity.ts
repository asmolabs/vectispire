import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { boolColumn, floatColumn, intColumn, stringColumn, textColumn, timestampColumn } from '../columns';

/**
 * Un constat brut, tel qu'un scanner l'a produit, rattaché à son scan.
 *
 * Distinct d'un problème : un constat appartient à **une** exécution, un problème vit à
 * travers les scans et porte l'historique et la décision de triage. C'est la
 * réconciliation par empreinte qui relie les deux.
 */
@Entity('finding')
export class Finding {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column({ ...intColumn(), name: 'scan_id' })
    scanId!: number;

    @Column(stringColumn(50))
    type!: string;

    @Column(stringColumn(50, { nullable: true }))
    severity!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    identifier!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'package_name' })
    packageName!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'package_version' })
    packageVersion!: string | null;

    @Column(stringColumn(255, { nullable: true }))
    purl!: string | null;

    @Column({ ...stringColumn(500, { nullable: true }), name: 'file_path' })
    filePath!: string | null;

    /** Quel outil l'a produit : `grype`, `osv`, `gitleaks`, `checkov`, `ollama:<modèle>`. */
    @Column(stringColumn(50))
    source!: string;

    @Column({ ...floatColumn({ nullable: true }), name: 'epss_score' })
    epssScore!: number | null;

    @Column({ ...boolColumn(), name: 'is_kev' })
    isKev!: boolean;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;

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

    @Column({ ...intColumn({ nullable: true }), name: 'issue_id' })
    issueId!: number | null;

    /** `null` signifie « pas de graphe de dépendances », pas « faux ». */
    @Column({ ...boolColumn({ nullable: true }), name: 'is_direct_dependency' })
    isDirectDependency!: boolean | null;

    @Column(intColumn({ nullable: true }))
    line!: number | null;

    @Column(textColumn({ nullable: true }))
    description!: string | null;
}
