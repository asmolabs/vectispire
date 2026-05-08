import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SettingsService } from './settings.service';
import { SettingsController } from './settings.controller';
import { Setting } from './entities/setting.entity';
import { MailModule } from '../mail/mail.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { RepositoryModule } from '../repository/repository.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Setting]),
    forwardRef(() => MailModule),
    forwardRef(() => NotificationsModule),
    forwardRef(() => RepositoryModule),
  ],
  controllers: [SettingsController],
  providers: [SettingsService],
  exports: [SettingsService],
})
export class SettingsModule {}
