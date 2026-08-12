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

    @Column({ ...intColumn({ nullable: true }), name: 'scan_interval_minutes' })
    scanIntervalMinutes!: number | null;

    @Column({ ...stringColumn(255, { nullable: true }), name: 'scan_cron' })
    scanCron!: string | null;

    @Column({ ...timestampColumn({ nullable: true }), name: 'last_scheduled_scan_at' })
    lastScheduledScanAt!: Date | null;
}
