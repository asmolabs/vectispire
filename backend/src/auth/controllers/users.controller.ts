import { Controller, Get, Patch, Body, Param, UseGuards } from '@nestjs/common';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';
import { UserRole } from '../enums/user-role.enum';
import { AuthService } from '../services/auth.service';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../entities/user.entity';
import { Repository } from 'typeorm';

@Controller('users')
@UseGuards(RolesGuard)
export class UsersController {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  @Get()
  @Roles(UserRole.SUPERUSER)
  findAll() {
    return this.userRepository.find({
      order: { createdAt: 'DESC' }
    });
  }

  @Patch(':id/role')
  @Roles(UserRole.SUPERUSER)
  async updateRole(@Param('id') id: string, @Body('role') role: UserRole) {
    await this.userRepository.update(+id, { role });
    return this.userRepository.findOne({ where: { id: +id } });
  }

  @Patch(':id/active')
  @Roles(UserRole.SUPERUSER)
  async updateActive(@Param('id') id: string, @Body('isActive') isActive: boolean) {
    await this.userRepository.update(+id, { isActive });
    return this.userRepository.findOne({ where: { id: +id } });
  }
}

