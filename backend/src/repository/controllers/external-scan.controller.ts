import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { ApiKeyAuthGuard } from '../../auth/guards/api-key-auth.guard';
import { RepositoryService } from '../../repository/services/repository.service';
import { ExternalScanDto } from '../dto/external-scan.dto';

@Controller('api/scan')
export class ExternalScanController {
  constructor(private readonly repositoryService: RepositoryService) {}

  @Post()
  @UseGuards(ApiKeyAuthGuard)
  async triggerExternalScan(@Body() dto: ExternalScanDto) {
    // Re-use create method which finds or creates the repo and triggers a scan
    return this.repositoryService.create({
      url: dto.url,
      branch: dto.branch || 'main',
      subPath: dto.subPath || '',
      sshKeyId: dto.sshKeyId,
    });
  }
}
