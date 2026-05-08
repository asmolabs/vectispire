import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

@Injectable()
export class AuditLogService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogger: Repository<AuditLog>,
  ) {}

  async findAll(): Promise<AuditLog[]> {
    return this.auditLogger.find({
      order: { timestamp: 'DESC' },
    });
  }

  async findByOrder(order: 'ASC' | 'DESC' = 'DESC'): Promise<AuditLog[]> {
    return this.auditLogger.find({
      order: { timestamp: order },
    });
  }

  async logAction(logData: {
    userId: number | null;
    resourceId: string;
    operationType: 'CREATE' | 'UPDATE' | 'DELETE' | 'SCAN_TRIGGER' | 'LOGIN_SUCCESSFUL' | 'LOGOUT_SUCCESSFUL' | 'LOGOUT_FAILED_AUTH';
    description: string;
  }): Promise<AuditLog> {
    const log = this.auditLogger.create({
        ...logData,
        userId: logData.userId ? String(logData.userId) : null
    });
    return this.auditLogger.save(log);
  }
}