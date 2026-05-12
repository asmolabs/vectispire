import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { SettingsService } from '../../settings/services/settings.service';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(
    @Inject(forwardRef(() => SettingsService))
    private settingsService: SettingsService
  ) {}

  private async createTransporter() {
    const settings = await this.settingsService.getEmailSettings();
    if (!settings.smtpHost || !settings.smtpPort) {
      this.logger.warn('SMTP settings are not fully configured. Email will not be sent.');
      return null;
    }

    this.logger.log(`Creating SMTP transporter for ${settings.smtpHost}:${settings.smtpPort}`);
    return nodemailer.createTransport({
      host: settings.smtpHost,
      port: parseInt(settings.smtpPort, 10),
      secure: parseInt(settings.smtpPort, 10) === 465,
      requireTLS: parseInt(settings.smtpPort, 10) === 587, // Force STARTTLS for port 587
      auth: settings.smtpUser ? {
        user: settings.smtpUser,
        pass: settings.smtpPass || '',
      } : undefined,
      tls: {
        rejectUnauthorized: false // Better compatibility with various SMTP servers
      }
    });
  }

  async sendVulnerabilityAlert(scanId: string, projectName: string, summary: any, emails: string) {
    const transporter = await this.createTransporter();
    if (!transporter) return;

    const emailSettings = await this.settingsService.getEmailSettings();
    const fromAddress = emailSettings.smtpFrom || '"Zanshin Security" <noreply@zanshin.local>';

    const htmlContent = `
      <h2>Alerte de Sécurité Zanshin</h2>
      <p>Des vulnérabilités ont été détectées lors du scan <strong>${scanId}</strong> pour le projet <strong>${projectName}</strong>.</p>
      <h3>Résumé des vulnérabilités :</h3>
      <ul>
        <li><strong>Critique :</strong> ${summary.critical}</li>
        <li><strong>Élevé :</strong> ${summary.high}</li>
        <li><strong>Moyen :</strong> ${summary.medium}</li>
        <li><strong>Faible :</strong> ${summary.low}</li>
        <li><strong>Négligeable :</strong> ${summary.negligible}</li>
        <li><strong>Inconnu :</strong> ${summary.unknown}</li>
      </ul>
      <p>Veuillez consulter le tableau de bord Zanshin pour plus de détails.</p>
    `;

    try {
      const info = await transporter.sendMail({
        from: fromAddress,
        to: emails, // comma separated list
        subject: `[Zanshin Alert] Vulnérabilités détectées - ${projectName}`,
        html: htmlContent,
      });
      this.logger.log(`Alert email sent to ${emails}: ${info.messageId}`);
    } catch (error) {
      this.logger.error(`Failed to send alert email: ${error.message}`, error.stack);
    }
  }

  async sendTestEmail(targetEmail: string) {
    const transporter = await this.createTransporter();
    if (!transporter) {
      throw new Error('SMTP non configuré (Hôte ou Port manquant)');
    }

    const emailSettings = await this.settingsService.getEmailSettings();
    const fromAddress = emailSettings.smtpFrom || '"Zanshin Test" <test@zanshin.local>';

    this.logger.log(`Sending test email to ${targetEmail}`);
    
    try {
      const result = await transporter.sendMail({
        from: fromAddress,
        to: targetEmail,
        subject: '[Zanshin] Test de configuration SMTP',
        text: 'Félicitations ! Votre configuration SMTP Zanshin fonctionne correctement.',
        html: '<h2>Test de configuration Zanshin</h2><p>Félicitations ! Votre configuration SMTP Zanshin fonctionne correctement.</p>'
      });
      this.logger.log(`Test email sent: ${result.messageId}`);
      return result;
    } catch (error) {
      this.logger.error(`SMTP Test failed: ${error.message}`);
      throw new Error(`Erreur SMTP : ${error.message}`);
    }
  }
}
