import { Column, Entity, PrimaryColumn } from 'typeorm';
import { stringColumn, timestampColumn } from '../columns';

/**
 * Le bail du travail périodique : une ligne par tâche exclusive.
 *
 * Une ligne plutôt qu'un verrou consultatif PostgreSQL, parce que le mécanisme doit
 * rester portable. La primitive est un **UPDATE conditionnel dont le nombre de lignes
 * touchées désigne le gagnant** — plus faible que `FOR UPDATE SKIP LOCKED`, et
 * suffisant ici : deux instances se croyant brièvement chef font un tick dupliqué, pas
 * une ligne corrompue, et le tick suivant tranche.
 */
@Entity('t_leader_lease')
export class LeaderLease {
    @PrimaryColumn({ type: 'character varying', length: 64 })
    name!: string;

    @Column(stringColumn(64, { nullable: true }))
    holder!: string | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'acquired_at' })
    acquiredAt!: Date | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'expires_at' })
    expiresAt!: Date | null;

    @Column({ ...timestampColumn(), name: 'updated_at' })
    updatedAt!: Date;
}
