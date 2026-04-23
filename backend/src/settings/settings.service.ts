import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Setting } from './entities/setting.entity';
import { UpdateAuthSettingsDto } from './dto/update-auth-settings.dto';
import { UpdateEmailSettingsDto } from './dto/update-email-settings.dto';
import { UpdateAlertSettingsDto } from './dto/update-alert-settings.dto';

@Injectable()
export class SettingsService implements OnModuleInit {
  constructor(
    @InjectRepository(Setting)
    private settingsRepository: Repository<Setting>,
  ) {}

  async onModuleInit() {
    await this.initializeSettings();
  }

  private async initializeSettings() {
    const defaultSettings = [
      { key: 'AUTH_GITHUB_ENABLED', value: 'false' },
      { key: 'AUTH_KEYCLOAK_ENABLED', value: 'false' },
      { key: 'SMTP_HOST', value: '' },
      { key: 'SMTP_PORT', value: '' },
      { key: 'SMTP_USER', value: '' },
      { key: 'SMTP_PASS', value: '' },
      { key: 'SMTP_FROM', value: '' },
      { key: 'ALERT_EMAILS', value: '' },
      { key: 'ALERT_MIN_SEVERITY', value: 'HIGH' },
      { key: 'TEAMS_WEBHOOK_URL', value: '' },
      { key: 'TEAMS_ENABLED', value: 'false' },
    ];

    for (const setting of defaultSettings) {
      const exists = await this.settingsRepository.findOne({ where: { key: setting.key } });
      if (!exists) {
        await this.settingsRepository.save(setting);
      }
    }
  }

  // --- Auth Settings ---
  async getAuthSettings() {
    const githubSetting = await this.settingsRepository.findOne({ where: { key: 'AUTH_GITHUB_ENABLED' } });
    const keycloakSetting = await this.settingsRepository.findOne({ where: { key: 'AUTH_KEYCLOAK_ENABLED' } });

    return {
      githubEnabled: githubSetting?.value === 'true',
      keycloakEnabled: keycloakSetting?.value === 'true',
    };
  }

  async updateAuthSettings(dto: UpdateAuthSettingsDto) {
    if (dto.githubEnabled !== undefined) {
      await this.settingsRepository.save({ key: 'AUTH_GITHUB_ENABLED', value: dto.githubEnabled.toString() });
    }
    if (dto.keycloakEnabled !== undefined) {
      await this.settingsRepository.save({ key: 'AUTH_KEYCLOAK_ENABLED', value: dto.keycloakEnabled.toString() });
    }
    return this.getAuthSettings();
  }

  // --- Email Settings ---
  async getEmailSettings() {
    const host = await this.settingsRepository.findOne({ where: { key: 'SMTP_HOST' } });
    const port = await this.settingsRepository.findOne({ where: { key: 'SMTP_PORT' } });
    const user = await this.settingsRepository.findOne({ where: { key: 'SMTP_USER' } });
    const pass = await this.settingsRepository.findOne({ where: { key: 'SMTP_PASS' } });
    const from = await this.settingsRepository.findOne({ where: { key: 'SMTP_FROM' } });

    return {
      smtpHost: host?.value || '',
      smtpPort: port?.value || '',
      smtpUser: user?.value || '',
      smtpPass: pass?.value || '',
      smtpFrom: from?.value || '',
    };
  }

  async updateEmailSettings(dto: UpdateEmailSettingsDto) {
    if (dto.smtpHost !== undefined) await this.settingsRepository.save({ key: 'SMTP_HOST', value: dto.smtpHost });
    if (dto.smtpPort !== undefined) await this.settingsRepository.save({ key: 'SMTP_PORT', value: dto.smtpPort });
    if (dto.smtpUser !== undefined) await this.settingsRepository.save({ key: 'SMTP_USER', value: dto.smtpUser });
    if (dto.smtpPass !== undefined) await this.settingsRepository.save({ key: 'SMTP_PASS', value: dto.smtpPass });
    if (dto.smtpFrom !== undefined) await this.settingsRepository.save({ key: 'SMTP_FROM', value: dto.smtpFrom });
    return this.getEmailSettings();
  }

  // --- Alert Settings ---
  async getAlertSettings() {
    const emails = await this.settingsRepository.findOne({ where: { key: 'ALERT_EMAILS' } });
    const minSeverity = await this.settingsRepository.findOne({ where: { key: 'ALERT_MIN_SEVERITY' } });

    return {
      alertEmails: emails?.value || '',
      alertMinSeverity: minSeverity?.value || 'HIGH',
    };
  }

  async updateAlertSettings(dto: UpdateAlertSettingsDto) {
    if (dto.alertEmails !== undefined) await this.settingsRepository.save({ key: 'ALERT_EMAILS', value: dto.alertEmails });
    if (dto.alertMinSeverity !== undefined) await this.settingsRepository.save({ key: 'ALERT_MIN_SEVERITY', value: dto.alertMinSeverity });
    return this.getAlertSettings();
  }

  // --- Teams Settings ---
  async getTeamsSettings() {
    const url = await this.settingsRepository.findOne({ where: { key: 'TEAMS_WEBHOOK_URL' } });
    const enabled = await this.settingsRepository.findOne({ where: { key: 'TEAMS_ENABLED' } });

    return {
      webhookUrl: url?.value || '',
      enabled: enabled?.value === 'true',
    };
  }

  async updateTeamsSettings(dto: { webhookUrl?: string, enabled?: boolean }) {
    if (dto.webhookUrl !== undefined) await this.settingsRepository.save({ key: 'TEAMS_WEBHOOK_URL', value: dto.webhookUrl });
    if (dto.enabled !== undefined) await this.settingsRepository.save({ key: 'TEAMS_ENABLED', value: dto.enabled.toString() });
    return this.getTeamsSettings();
  }
}
