import { Entity, PrimaryGeneratedColumn, Column, OneToMany, Unique } from 'typeorm';
import { Scan } from '../../repository/entities/scan.entity';

@Entity('container')
@Unique(['registry', 'imageName', 'tag'])
export class Container {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: true })
  registry: string;

  @Column()
  imageName: string;

  @Column({ default: 'latest' })
  tag: string;

  @OneToMany(() => Scan, (scan) => scan.container)
  scans: Scan[];

  @Column({ nullable: true })
  scanIntervalMinutes: number;

  @Column({ nullable: true })
  scanCron: string;

  @Column({ nullable: true })
  lastScheduledScanAt: Date;
}
