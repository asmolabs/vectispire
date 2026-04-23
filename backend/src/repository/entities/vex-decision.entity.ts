import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Repository } from './repository.entity';

@Entity()
export class VexDecision {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  vulnerabilityId: string; // e.g. CVE-2023-1234

  @Column()
  packageName: string;

  @Column({ nullable: true })
  purl: string; // Package URL

  @Column()
  status: string; // not_affected, affected, fixed, under_investigation

  @Column({ nullable: true })
  justification: string; // component_not_present, vulnerable_code_not_present, etc.

  @Column({ nullable: true })
  response: string; // will_not_fix, update, rollback, etc.

  @Column({ type: 'text', nullable: true })
  comment: string;

  @ManyToOne(() => Repository, (repository) => repository.vexDecisions)
  repository: Repository;

  @Column()
  repositoryId: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
