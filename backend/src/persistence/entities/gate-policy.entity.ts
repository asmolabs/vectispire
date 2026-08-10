import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { boolColumn, intColumn, stringColumn, textColumn, timestampColumn } from '../columns';

/**
 * Une version d'une politique de gate, globale ou propre à une cible.
 *
 * Versionnée plutôt que modifiée sur place : changer ce qui fait échouer une
 * compilation est une décision de sécurité, et savoir qui l'a prise et quand vaut
 * autant que la valeur actuelle.
 *
 * La contrainte d'unicité porte sur `(target_kind, target_id, is_active)`, et
 * `isActive` est **nullable** exprès : SQL ignore les NULL dans un index unique, donc
 * les versions périmées peuvent coexister sans se gêner tant qu'elles portent `null`
 * plutôt que `false`. Une seule version active par portée, sans colonne de plus.
 *
 * La politique globale est stockée avec `targetId = 0`.
 */
@Entity('gate_policy')
export class GatePolicyRow {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column({ ...stringColumn(20), name: 'target_kind' })
    targetKind!: string;

    @Column({ ...intColumn(), name: 'target_id' })
    targetId!: number;

    @Column(intColumn())
    version!: number;

    @Column({ ...boolColumn({ nullable: true }), name: 'is_active' })
    isActive!: boolean | null;

    /** `null` désactive entièrement la règle de sévérité — utile pour ne barrer que sur KEV. */
    @Column({ ...stringColumn(20, { nullable: true }), name: 'fail_on_severity' })
    failOnSeverity!: string | null;

    @Column({ ...boolColumn(), name: 'fail_on_kev' })
    failOnKev!: boolean;

    @Column({ ...boolColumn(), name: 'fixable_only' })
    fixableOnly!: boolean;

    @Column({ ...boolColumn(), name: 'include_triaged' })
    includeTriaged!: boolean;

    @Column({ ...boolColumn(), name: 'include_ai_review' })
    includeAiReview!: boolean;

    @Column(textColumn({ nullable: true }))
    note!: string | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'created_by' })
    createdBy!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;
}
