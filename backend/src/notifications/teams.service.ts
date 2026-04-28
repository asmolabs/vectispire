import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { SettingsService } from '../settings/settings.service';

@Injectable()
export class TeamsService {
  private readonly logger = new Logger(TeamsService.name);

  constructor(
    @Inject(forwardRef(() => SettingsService))
    private settingsService: SettingsService
  ) {}

  async sendVulnerabilityAlert(scanId: string, projectName: string, summary: any) {
    const settings = await this.settingsService.getTeamsSettings();
    if (!settings.enabled || !settings.webhookUrl || !this.isValidWebhookUrl(settings.webhookUrl)) {
      this.logger.warn(`Teams notification disabled or webhook URL (${settings.webhookUrl}) is invalid/unsafe.`);
      return;
    }

    this.logger.log(`Sending Teams notification for scan ${scanId}`);

    const payload = {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          content: {
            type: "AdaptiveCard",
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            version: "1.2",
            body: [
              {
                type: "TextBlock",
                size: "Medium",
                weight: "Bolder",
                text: `🚨 Alerte de Sécurité Zanshin - ${projectName}`,
                color: "Attention"
              },
              {
                type: "TextBlock",
                text: `Des vulnérabilités ont été détectées lors du scan **${scanId}**.`,
                wrap: true
              },
              {
                type: "FactSet",
                facts: [
                  { title: "Critique", value: `${summary.critical}` },
                  { title: "Élevé", value: `${summary.high}` },
                  { title: "Moyen", value: `${summary.medium}` },
                  { title: "Faible", value: `${summary.low}` }
                ]
              }
            ],
            actions: [
              {
                type: "Action.OpenUrl",
                title: "Voir le rapport",
                url: "http://localhost:4200" // Idéalement l'URL de votre instance
              }
            ]
          }
        }
      ]
    };

    try {
      const response = await fetch(settings.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Teams Webhook failed: ${response.status} ${errorText}`);
      }
      
      this.logger.log('Teams notification sent successfully');
    } catch (error) {
      this.logger.error(`Failed to send Teams notification: ${error.message}`);
    }
  }

  async sendTestMessage(webhookUrl: string) {
    if (!this.isValidWebhookUrl(webhookUrl)) {
      throw new Error('Invalid or unsafe webhook URL provided.');
    }

    const payload = {
      type: "message",
// ... rest of the code unchanged
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          content: {
            type: "AdaptiveCard",
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            version: "1.2",
            body: [
              {
                type: "TextBlock",
                size: "Large",
                weight: "Bolder",
                text: "Zanshin - Test de Connexion Teams"
              },
              {
                type: "TextBlock",
                text: "Félicitations ! Votre webhook Teams est correctement configuré.",
                wrap: true
              }
            ]
          }
        }
      ]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Erreur Teams (${response.status}): ${errorText}`);
    }

    return { message: 'Message de test envoyé' };
  }
}
