import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { intColumn, stringColumn, timestampColumn } from '../columns';

/** Une image de conteneur surveillée. */
@Entity('t_container')
export class Container {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column(stringColumn(255, { nullable: true }))
    registry!: string | null;

    @Column({ ...stringColumn(), name: 'image_name' })
    imageName!: string;

    @Column(stringColumn())
    tag!: string;

    /**
     * L'étiquette qu'un agent doit porter pour scanner cette image. `null` : aucune.
     *
     * Même règle que pour un dépôt : tirer une image d'un registre privé demande parfois un
     * agent placé là où ce registre est joignable, et ce placement ne doit pas lui donner
     * accès au reste de la file.
     */
    @Column({ ...stringColumn(255, { nullable: true }), name: 'required_agent_label' })
    requiredAgentLabel!: string | null;

    @Column({ ...intColumn({ nullable: true }), name: 'scan_interval_minutes' })
    scanIntervalMinutes!: number | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'scan_cron' })
    scanCron!: string | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'last_scheduled_scan_at' })
    lastScheduledScanAt!: Date | null;
}
