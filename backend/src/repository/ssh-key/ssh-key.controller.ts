import { Controller, Get, Post, Body, Param, Delete, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { SSHKeyService } from './ssh-key.service';
import { CreateSSHKeyDto } from './dto/create-ssh-key.dto';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { UserRole } from '../../auth/enums/user-role.enum';

@Controller('ssh-keys')
export class SSHKeyController {
  constructor(private readonly sshKeyService: SSHKeyService) {}

  @Post()
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  create(@Body() createSSHKeyDto: CreateSSHKeyDto) {
    return this.sshKeyService.create(createSSHKeyDto);
  }

  @Post('generate')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  generate() {
    return this.sshKeyService.generateKeyPair();
  }

  @Get()
  findAll() {
    return this.sshKeyService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.sshKeyService.findOne(id);
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@Param('id') id: string) {
    return this.sshKeyService.remove(id);
  }
}
