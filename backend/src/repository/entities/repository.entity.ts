import { Entity, Column, PrimaryGeneratedColumn, OneToMany, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Scan } from './scan.entity';
import { VexDecision } from './vex-decision.entity';
import { SSHKey } from './ssh-key.entity';

@Entity()
@Index(['url', 'branch', 'subPath'], { unique: true })
export class Repository {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  url: string;

  @Column({ default: 'main' })
  branch: string;

  @Column({ default: '' })
  subPath: string;

  @Column({ nullable: true })
  name: string;

  @OneToMany(() => Scan, (scan) => scan.repository)
  scans: Scan[];

  @OneToMany(() => VexDecision, (vex) => vex.repository)
  vexDecisions: VexDecision[];

  @ManyToOne(() => SSHKey, (sshKey) => sshKey.repositories, { nullable: true })
  @JoinColumn({ name: 'sshKeyId' })
  sshKey: SSHKey;

  @Column({ nullable: true })
  sshKeyId: string;

  @Column({ nullable: true })
  scanIntervalMinutes: number;

  @Column({ nullable: true })
  lastScheduledScanAt: Date;

  @Column({ nullable: true })
  scanCron: string;
}
