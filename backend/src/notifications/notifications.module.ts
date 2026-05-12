import { Module, forwardRef } from '@nestjs/common';
import { TeamsService } from './services/teams.service';
import { SettingsModule } from '../settings/settings.module';

@Module({
  imports: [forwardRef(() => SettingsModule)],
  providers: [TeamsService],
  exports: [TeamsService],
})
export class NotificationsModule {}
