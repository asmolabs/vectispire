import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, CreateDateColumn, JoinColumn } from 'typeorm';
import { Repository } from './repository.entity';

@Entity()
export class Scan {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  branch: string;

  @Column({ default: '' })
  subPath: string;

  @Column({ default: 'pending' })
  status: string;

  @Column({ type: 'simple-json', nullable: true })
  sbom: any;

  @Column({ type: 'simple-json', nullable: true })
  cves: any;

  @Column({ type: 'simple-json', nullable: true })
  summary: any;

  @Column({ nullable: true })
  durationMs: number;

  @Column({ default: 0 })
  findingsCount: number;

  @Column({ nullable: true })
  error: string;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ type: 'varchar', nullable: true })
  version?: string | null;

  @Column({ type: 'varchar', nullable: true })
  projectType?: string | null;


  @ManyToOne(() => Repository, (repo) => repo.scans, { onDelete: 'CASCADE', nullable: true })
  @JoinColumn({ name: 'repoId' })
  repository: Repository;

  @Column({ nullable: true })
  repoId: number;

  @ManyToOne('Container', 'scans', { onDelete: 'CASCADE', nullable: true })
  @JoinColumn({ name: 'containerId' })
  container: any;

  @Column({ nullable: true })
  containerId: number;
}
