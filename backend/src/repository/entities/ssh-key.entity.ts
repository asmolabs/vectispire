import { Entity, Column, PrimaryColumn, OneToMany, CreateDateColumn } from 'typeorm';
import { Repository } from './repository.entity';

@Entity()
export class SSHKey {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ type: 'text' })
  privateKey: string; // Stored encrypted

  @Column({ type: 'text', nullable: true })
  publicKey: string;

  @CreateDateColumn()
  createdAt: Date;

  @OneToMany(() => Repository, (repo) => repo.sshKey)
  repositories: Repository[];
}
