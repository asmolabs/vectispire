import { Controller, Get, Post, Body, Patch, Param, Delete, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RepositoryService } from './repository.service';
import { CreateRepositoryDto } from './dto/create-repository.dto';
import { UpdateRepositoryDto } from './dto/update-repository.dto';
import { CreateVexDecisionDto } from './dto/create-vex-decision.dto';
import type { Response } from 'express';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/enums/user-role.enum';

@Controller('repository')
export class RepositoryController {
  constructor(private readonly repositoryService: RepositoryService) {}

  @Post()
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  create(@Body() createRepositoryDto: CreateRepositoryDto) {
    return this.repositoryService.create(createRepositoryDto);
  }

  @Post(':id/scan')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  triggerScan(@Param('id') id: string, @Body('branch') branch: string, @Body('subPath') subPath?: string) {
    return this.repositoryService.triggerScan(+id, '', branch, subPath);
  }

  @Get()
  findAll() {
    return this.repositoryService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.repositoryService.findOne(+id);
  }

  @Patch(':id')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  update(@Param('id') id: string, @Body() updateRepositoryDto: UpdateRepositoryDto) {
    return this.repositoryService.update(+id, updateRepositoryDto);
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  remove(@Param('id') id: string) {
    return this.repositoryService.remove(+id);
  }

  @Delete(':repoId/scan/:scanId')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  removeScan(@Param('repoId') _repoId: string, @Param('scanId') scanId: string) {
    return this.repositoryService.removeScan(+scanId);
  }

  @Post(':id/vex')
  upsertVex(@Param('id') id: string, @Body() dto: CreateVexDecisionDto) {
    return this.repositoryService.upsertVexDecision(+id, dto);
  }

  @Get(':id/vex')
  getVex(@Param('id') id: string) {
    return this.repositoryService.getVexDecisions(+id);
  }

  @Get(':id/openvex')
  async exportOpenVex(@Param('id') id: string, @Res() res: Response) {
    const doc = await this.repositoryService.exportOpenVex(+id);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=openvex-repo-${id}.json`);
    return res.send(doc);
  }
}
