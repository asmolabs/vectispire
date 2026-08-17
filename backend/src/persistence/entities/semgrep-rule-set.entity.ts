import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';
import { bigIntColumn, boolColumn, intColumn, jsonColumn, stringColumn, textColumn, timestampColumn } from '../columns';

/**
 * A Semgrep rule set uploaded by an operator.
 *
 * Zanshin bundles one rule; the public sets are not redistributable, so coverage arrives
 * from outside ([decision 0006](../../../../docs/architecture/decisions/0006-semgrep-rules-written-here.md)).
 * `ZANSHIN_SEMGREP_RULES_DIR` is one route and it is per-executor: every remote agent needs
 * the directory on its own filesystem, and the control plane cannot verify that it did.
 * Storing the rules here and letting every executor fetch them makes them identical by
 * construction.
 *
 * **The files live in one JSON column rather than one row each.** A rule set is written
 * once, read whole, and never queried by file: a row per file would buy a join and a
 * consistency problem — a fetch landing between two inserts would ship half a rule set,
 * which is exactly the silent partial coverage this table exists to prevent.
 *
 * `contentHash` is the identity an executor caches on, so an unchanged set is fetched once
 * rather than on every claim.
 */
@Entity('t_semgrep_rule_set')
@Index('uq_semgrep_rule_set_active', ['isActive'], { unique: true })
export class SemgrepRuleSet {
    @PrimaryGeneratedColumn()
    id!: number;

    /** The operator's name for this set. Display only. */
    @Column(stringColumn(255))
    name!: string;

    /**
     * `{ path, originalName, content }[]`, under the paths Zanshin generated.
     *
     * The uploaded names are kept alongside so a rule can be traced back to the file it came
     * from; they are never used as paths — see `domain/rules/rule-set.ts`.
     */
    @Column(jsonColumn())
    files!: unknown;

    /** SHA-256 over the generated paths and contents. What an executor caches on. */
    @Column({ ...stringColumn(64), name: 'content_hash' })
    contentHash!: string;

    /** How many rule ids the advisory extraction found. Display only. */
    @Column({ ...intColumn(), name: 'rule_count' })
    ruleCount!: number;

    @Column({ ...intColumn(), name: 'file_count' })
    fileCount!: number;

    @Column({ ...bigIntColumn(), name: 'size_bytes' })
    sizeBytes!: string;

    /**
     * At most one set is active, and it is the one that ships with every task.
     *
     * **Nullable rather than a plain boolean**, and that is the portable way to say "at most
     * one true" across these four engines: a unique index over `is_active` counts `NULL`s as
     * distinct on all of them, so inactive rows carry `NULL` and the active one carries
     * `true`. A `false` there would make the second deactivated set collide with the first.
     */
    @Column({ ...boolColumn({ nullable: true }), name: 'is_active' })
    isActive!: boolean | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'uploaded_by' })
    uploadedBy!: string | null;

    @Column({ ...timestampColumn(), name: 'uploaded_at' })
    uploadedAt!: Date;

    /**
     * What the operator was told they were about to lose, kept as a record of the decision.
     *
     * Activating a set whose rule ids differ resolves the open issues of the rules that
     * disappear — with their triage decisions. Recording the warning that was shown makes
     * "why did four hundred issues close that afternoon" answerable six months later.
     */
    @Column({ ...textColumn({ nullable: true }), name: 'activation_note' })
    activationNote!: string | null;
}
