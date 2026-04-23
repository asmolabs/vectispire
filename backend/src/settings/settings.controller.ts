import { Controller, Get, Put, Post, Body, UseGuards, Inject, forwardRef, BadRequestException } from '@nestjs/common';
import { SettingsService } from './settings.service';
import { MailService } from '../mail/mail.service';
import { TeamsService } from '../notifications/teams.service';
import { UpdateAuthSettingsDto } from './dto/update-auth-settings.dto';
import { UpdateEmailSettingsDto } from './dto/update-email-settings.dto';
import { UpdateAlertSettingsDto } from './dto/update-alert-settings.dto';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/enums/user-role.enum';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Public } from '../auth/decorators/public.decorator';

@Controller('settings')
export class SettingsController {
  constructor(
    private readonly settingsService: SettingsService,
    @Inject(forwardRef(() => MailService))
    private readonly mailService: MailService,
    @Inject(forwardRef(() => TeamsService))
    private readonly teamsService: TeamsService,
  ) {}

  @Public()
  @Get('auth')
  getAuthSettings() {
    return this.settingsService.getAuthSettings();
  }

  @Put('auth')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  updateAuthSettings(@Body() updateDto: UpdateAuthSettingsDto) {
    return this.settingsService.updateAuthSettings(updateDto);
  }

  @Get('email')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  getEmailSettings() {
    return this.settingsService.getEmailSettings();
  }

  @Put('email')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  updateEmailSettings(@Body() updateDto: UpdateEmailSettingsDto) {
    return this.settingsService.updateEmailSettings(updateDto);
  }

  @Get('alerting')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  getAlertSettings() {
    return this.settingsService.getAlertSettings();
  }

  @Put('alerting')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  updateAlertSettings(@Body() updateDto: UpdateAlertSettingsDto) {
    return this.settingsService.updateAlertSettings(updateDto);
  }

  @Post('email/test')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  async sendTestEmail(@Body('email') email: string) {
    try {
      console.log(`[DEBUG] Attempting to send test email to: ${email}`);
      if (!this.mailService) {
        throw new Error('MailService is undefined in SettingsController');
      }
      await this.mailService.sendTestEmail(email);
      return { message: 'Email de test envoyé avec succès' };
    } catch (error) {
      console.error(`[ERROR] sendTestEmail failed: ${error.message}`);
      throw new BadRequestException(error.message);
    }
  }

  @Get('teams')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  getTeamsSettings() {
    return this.settingsService.getTeamsSettings();
  }

  @Put('teams')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  updateTeamsSettings(@Body() updateDto: { webhookUrl?: string, enabled?: boolean }) {
    return this.settingsService.updateTeamsSettings(updateDto);
  }

  @Post('teams/test')
  @Roles(UserRole.ADMIN, UserRole.SUPERUSER)
  @UseGuards(RolesGuard)
  async sendTeamsTest(@Body('webhookUrl') webhookUrl: string) {
    return this.teamsService.sendTestMessage(webhookUrl);
  }
}
