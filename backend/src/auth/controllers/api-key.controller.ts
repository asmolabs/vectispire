import { Controller, Get, Post, Delete, Param, Body, UseGuards, Request } from '@nestjs/common';
import { ApiKeyService } from '../services/api-key.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { UserRole } from '../enums/user-role.enum';
import { Roles } from '../decorators/roles.decorator';

@Controller('auth/api-keys')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ApiKeyController {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  @Post()
  @Roles(UserRole.USER, UserRole.ADMIN, UserRole.SUPERUSER)
  async create(@Request() req: any, @Body('name') name: string) {
    return this.apiKeyService.create(req.user.userId, name);
  }

  @Get()
  @Roles(UserRole.USER, UserRole.ADMIN, UserRole.SUPERUSER)
  async findAll(@Request() req: any) {
    return this.apiKeyService.findAllForUser(req.user.userId);
  }

  @Delete(':id')
  @Roles(UserRole.USER, UserRole.ADMIN, UserRole.SUPERUSER)
  async remove(@Request() req: any, @Param('id') id: string) {
    return this.apiKeyService.remove(id, req.user.userId);
  }
}
