import { Controller, Get, UseGuards } from '@nestjs/common';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/enums/user-role.enum';
import { AuditLogService } from '../repository/audit-log.service';
import { AuditLog } from '../repository/entities/audit-log.entity';

@Controller('audit')
export class AuditController {
  constructor(private readonly auditLogService: AuditLogService) {}

  @UseGuards(RolesGuard)
  @Roles(UserRole.SUPERUSER)
  @Get()
  findAll() {
    // Return logs ordered by the most recent timestamp
    return this.auditLogService.findByOrder('DESC'); 
  }
}