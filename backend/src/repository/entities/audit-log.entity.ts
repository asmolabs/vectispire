import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('audit_logs')
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  // The user or system performing the action (Can be NULL if automated)
  userId: string | null;

  // Target resource ID (e.g., repoId, sshKeyId)
  resourceId: string;

  // Type of operation performed (CREATE, UPDATE, DELETE, SCAN_TRIGGER)
  operationType: 'CREATE' | 'UPDATE' | 'DELETE' | 'SCAN_TRIGGER';

  // Brief description of the change or event
  description: string;

  @CreateDateColumn()
  timestamp: Date;
}