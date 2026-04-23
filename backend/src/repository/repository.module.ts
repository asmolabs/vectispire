import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { RepositoryService } from './repository.service';
import { RepositoryController } from './repository.controller';
import { ExternalScanController } from './external-scan.controller';
import { Repository } from './entities/repository.entity';
import { Scan } from './entities/scan.entity';
import { VexDecision } from './entities/vex-decision.entity';
import { ScanProcessor } from './scan.processor';
import { NotificationGateway } from './notification.gateway';
import { SSHKeyModule } from './ssh-key/ssh-key.module';
import { EncryptionService } from '../common/encryption.service';
import { AuthModule } from '../auth/auth.module';
import { SchedulerService } from './scheduler.service';

import { ContainerModule } from '../container/container.module';
import { Container } from '../container/entities/container.entity';
import { SettingsModule } from '../settings/settings.module';
import { MailModule } from '../mail/mail.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Repository, Scan, VexDecision, Container]),
    BullModule.registerQueue({
      name: 'scan-queue',
    }),
    SSHKeyModule,
    forwardRef(() => AuthModule),
    ContainerModule,
    SettingsModule,
    MailModule,
  ],
  controllers: [RepositoryController, ExternalScanController],
  providers: [RepositoryService, ScanProcessor, NotificationGateway, EncryptionService, SchedulerService],
  exports: [NotificationGateway],
})
export class RepositoryModule {}

