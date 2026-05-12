import { Module, forwardRef } from '@nestjs/common';
import { MailService } from './services/mail.service';
import { SettingsModule } from '../settings/settings.module';

@Module({
  imports: [forwardRef(() => SettingsModule)],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
