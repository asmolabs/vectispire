import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CardModule } from 'primeng/card';
import { ToggleSwitchModule } from 'primeng/toggleswitch';
import { ButtonModule } from 'primeng/button';
import { ToastModule } from 'primeng/toast';
import { MessageService } from 'primeng/api';
import { TabsModule } from 'primeng/tabs';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { SelectModule } from 'primeng/select';
import { SettingsService, AuthSettings, EmailSettings, AlertSettings, TeamsSettings } from '../settings/settings.service';
import { forkJoin } from 'rxjs';

@Component({
  selector: 'app-admin-settings',
  standalone: true,
  imports: [
    CommonModule, 
    FormsModule, 
    CardModule, 
    ToggleSwitchModule, 
    ButtonModule, 
    ToastModule,
    TabsModule,
    InputTextModule,
    PasswordModule,
    SelectModule
  ],
  providers: [MessageService],
  template: `
    <div class="grid">
      <div class="col-12">
        <p-card header="Paramètres d'Administration">
          <p class="text-600 mb-4">
            Configurez les méthodes de connexion, les notifications et les alertes de sécurité.
          </p>

          <div *ngIf="loading" class="flex align-items-center justify-content-center p-4">
            <i class="pi pi-spin pi-spinner" style="font-size: 2rem"></i>
          </div>

          <p-tabs *ngIf="!loading" value="0">
            <p-tablist>
                <p-tab value="0">
                    <i class="pi pi-shield mr-2"></i>
                    <span>Authentification</span>
                </p-tab>
                <p-tab value="1">
                    <i class="pi pi-envelope mr-2"></i>
                    <span>Serveur SMTP</span>
                </p-tab>
                <p-tab value="2">
                    <i class="pi pi-bell mr-2"></i>
                    <span>Alertes Email</span>
                </p-tab>
                <p-tab value="3">
                    <i class="pi pi-microsoft mr-2"></i>
                    <span>Teams</span>
                </p-tab>
            </p-tablist>
            
            <p-tabpanels>
                <!-- Onglet Authentification -->
                <p-tabpanel value="0">
                    <div class="flex flex-column gap-4 mt-3">
                        <div class="flex align-items-center justify-content-between border-bottom-1 border-300 pb-3">
                        <div>
                            <div class="text-xl font-bold mb-1">Connexion Locale</div>
                            <div class="text-sm text-500">Activée par défaut (Nom d'utilisateur et mot de passe)</div>
                        </div>
                        <p-toggleswitch [ngModel]="true" [disabled]="true"></p-toggleswitch>
                        </div>

                        <div class="flex align-items-center justify-content-between border-bottom-1 border-300 pb-3">
                        <div>
                            <div class="text-xl font-bold mb-1">Connexion GitHub</div>
                            <div class="text-sm text-500">Permettre aux utilisateurs de se connecter via leur compte GitHub</div>
                        </div>
                        <p-toggleswitch [(ngModel)]="authSettings.githubEnabled" (onChange)="onSettingChange()"></p-toggleswitch>
                        </div>

                        <div class="flex align-items-center justify-content-between pb-3">
                        <div>
                            <div class="text-xl font-bold mb-1">Connexion Keycloak</div>
                            <div class="text-sm text-500">Permettre aux utilisateurs de se connecter via Keycloak (SSO)</div>
                        </div>
                        <p-toggleswitch [(ngModel)]="authSettings.keycloakEnabled" (onChange)="onSettingChange()"></p-toggleswitch>
                        </div>
                    </div>
                </p-tabpanel>

                <!-- Onglet SMTP -->
                <p-tabpanel value="1">
                    <div class="flex flex-column gap-3 mt-3">
                        <div class="grid">
                            <div class="col-12 md:col-8">
                                <label for="smtpHost" class="block font-bold mb-2">Hôte SMTP</label>
                                <input pInputText id="smtpHost" [(ngModel)]="emailSettings.smtpHost" (ngModelChange)="onSettingChange()" class="w-full" placeholder="ex: smtp.mailtrap.io" />
                            </div>
                            <div class="col-12 md:col-4">
                                <label for="smtpPort" class="block font-bold mb-2">Port</label>
                                <input pInputText id="smtpPort" [(ngModel)]="emailSettings.smtpPort" (ngModelChange)="onSettingChange()" class="w-full" placeholder="ex: 587" />
                            </div>
                            <div class="col-12 md:col-6">
                                <label for="smtpUser" class="block font-bold mb-2">Utilisateur SMTP</label>
                                <input pInputText id="smtpUser" [(ngModel)]="emailSettings.smtpUser" (ngModelChange)="onSettingChange()" class="w-full" />
                            </div>
                            <div class="col-12 md:col-6">
                                <label for="smtpPass" class="block font-bold mb-2">Mot de passe SMTP</label>
                                <p-password id="smtpPass" [(ngModel)]="emailSettings.smtpPass" (ngModelChange)="onSettingChange()" [feedback]="false" [toggleMask]="true" styleClass="w-full" inputStyleClass="w-full"></p-password>
                            </div>
                            <div class="col-12">
                                <label for="smtpFrom" class="block font-bold mb-2">Adresse de l'expéditeur (From)</label>
                                <input pInputText id="smtpFrom" [(ngModel)]="emailSettings.smtpFrom" (ngModelChange)="onSettingChange()" class="w-full" placeholder="ex: noreply@zanshin.local" />
                            </div>
                        </div>
                        <div class="mt-4 p-3 border-1 border-300 border-round bg-gray-50">
                            <div class="font-bold mb-3">Tester la configuration Email</div>
                            <div class="flex gap-2">
                                <input pInputText [(ngModel)]="testEmailAddress" class="flex-grow-1" placeholder="Email de destination pour le test" />
                                <p-button label="Envoyer un test" icon="pi pi-send" severity="secondary" [loading]="testingEmail" (onClick)="testEmail()" [disabled]="!emailSettings.smtpHost"></p-button>
                            </div>
                        </div>
                    </div>
                </p-tabpanel>

                <!-- Onglet Alertes Email -->
                <p-tabpanel value="2">
                    <div class="flex flex-column gap-3 mt-3">
                        <div class="field">
                            <label for="alertEmails" class="block font-bold mb-2">Adresses E-mail d'alerte</label>
                            <input pInputText id="alertEmails" [(ngModel)]="alertSettings.alertEmails" (ngModelChange)="onSettingChange()" class="w-full" placeholder="Séparées par des virgules (ex: admin@zanshin.com, secu@zanshin.com)" />
                            <small class="text-500">Un e-mail sera envoyé à ces adresses lors de la détection de failles.</small>
                        </div>

                        <div class="field mt-3">
                            <label for="alertMinSeverity" class="block font-bold mb-2">Sévérité minimale pour alerter (Email & Teams)</label>
                            <p-select id="alertMinSeverity" [options]="severityOptions" [(ngModel)]="alertSettings.alertMinSeverity" (ngModelChange)="onSettingChange()" optionLabel="label" optionValue="value" styleClass="w-full md:w-20rem"></p-select>
                            <small class="block mt-1 text-500">Seuls les scans détectant des vulnérabilités de ce niveau ou supérieur déclencheront une notification.</small>
                        </div>
                    </div>
                </p-tabpanel>

                <!-- Onglet Teams -->
                <p-tabpanel value="3">
                    <div class="flex flex-column gap-3 mt-3">
                        <div class="flex align-items-center justify-content-between border-bottom-1 border-300 pb-3 mb-3">
                            <div>
                                <div class="text-xl font-bold mb-1">Notifications Teams</div>
                                <div class="text-sm text-500">Envoyer les alertes de sécurité vers un canal Microsoft Teams</div>
                            </div>
                            <p-toggleswitch [(ngModel)]="teamsSettings.enabled" (onChange)="onSettingChange()"></p-toggleswitch>
                        </div>

                        <div class="field" [class.opacity-50]="!teamsSettings.enabled">
                            <label for="teamsWebhook" class="block font-bold mb-2">URL du Webhook Teams</label>
                            <input pInputText id="teamsWebhook" [(ngModel)]="teamsSettings.webhookUrl" (ngModelChange)="onSettingChange()" class="w-full" placeholder="https://outlook.office.com/webhook/..." [disabled]="!teamsSettings.enabled" />
                            <small class="text-500">Utilisez un connecteur "Incoming Webhook" (ou un Workflow Teams) pour obtenir cette URL.</small>
                        </div>

                        <div class="mt-4 p-3 border-1 border-300 border-round bg-gray-50" *ngIf="teamsSettings.enabled">
                            <div class="font-bold mb-3">Tester la connexion Teams</div>
                            <div class="flex gap-2">
                                <p-button label="Envoyer un message de test" icon="pi pi-microsoft" severity="secondary" [loading]="testingTeams" (onClick)="testTeams()" [disabled]="!teamsSettings.webhookUrl"></p-button>
                            </div>
                        </div>
                    </div>
                </p-tabpanel>
            </p-tabpanels>
          </p-tabs>

          <div class="flex justify-content-end mt-4" *ngIf="!loading">
            <p-button label="Enregistrer les modifications" icon="pi pi-save" [loading]="saving" (onClick)="saveSettings()" [disabled]="!hasChanges"></p-button>
          </div>
        </p-card>
      </div>
    </div>
    <p-toast></p-toast>
  `
})
export class AdminSettingsComponent implements OnInit {
  private settingsService = inject(SettingsService);
  private messageService = inject(MessageService);

  authSettings: AuthSettings = { githubEnabled: false, keycloakEnabled: false };
  emailSettings: EmailSettings = { smtpHost: '', smtpPort: '', smtpUser: '', smtpPass: '', smtpFrom: '' };
  alertSettings: AlertSettings = { alertEmails: '', alertMinSeverity: 'HIGH' };
  teamsSettings: TeamsSettings = { webhookUrl: '', enabled: false };

  originalAuth: AuthSettings = { githubEnabled: false, keycloakEnabled: false };
  originalEmail: EmailSettings = { smtpHost: '', smtpPort: '', smtpUser: '', smtpPass: '', smtpFrom: '' };
  originalAlert: AlertSettings = { alertEmails: '', alertMinSeverity: 'HIGH' };
  originalTeams: TeamsSettings = { webhookUrl: '', enabled: false };
  
  loading = true;
  saving = false;
  testingEmail = false;
  testingTeams = false;
  hasChanges = false;
  testEmailAddress = '';

  severityOptions = [
    { label: 'CRITIQUE (Critical)', value: 'CRITICAL' },
    { label: 'ÉLEVÉ (High)', value: 'HIGH' },
    { label: 'MOYEN (Medium)', value: 'MEDIUM' },
    { label: 'FAIBLE (Low)', value: 'LOW' }
  ];

  ngOnInit() {
    this.loadSettings();
  }

  loadSettings() {
    this.loading = true;
    forkJoin({
      auth: this.settingsService.getAuthSettings(),
      email: this.settingsService.getEmailSettings(),
      alert: this.settingsService.getAlertSettings(),
      teams: this.settingsService.getTeamsSettings()
    }).subscribe({
      next: (results) => {
        this.authSettings = { ...results.auth };
        this.originalAuth = { ...results.auth };

        this.emailSettings = { ...results.email };
        this.originalEmail = { ...results.email };

        this.alertSettings = { ...results.alert };
        this.originalAlert = { ...results.alert };

        this.teamsSettings = { ...results.teams };
        this.originalTeams = { ...results.teams };

        this.loading = false;
        this.hasChanges = false;
      },
      error: () => {
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de charger les paramètres' });
        this.loading = false;
      }
    });
  }

  onSettingChange() {
    this.hasChanges = 
      JSON.stringify(this.authSettings) !== JSON.stringify(this.originalAuth) ||
      JSON.stringify(this.emailSettings) !== JSON.stringify(this.originalEmail) ||
      JSON.stringify(this.alertSettings) !== JSON.stringify(this.originalAlert) ||
      JSON.stringify(this.teamsSettings) !== JSON.stringify(this.originalTeams);
  }

  testEmail() {
    if (!this.testEmailAddress) {
      this.messageService.add({ severity: 'warn', summary: 'Attention', detail: 'Veuillez saisir une adresse email pour le test' });
      return;
    }

    this.testingEmail = true;
    this.settingsService.sendTestEmail(this.testEmailAddress).subscribe({
      next: () => {
        this.testingEmail = false;
        this.messageService.add({ severity: 'success', summary: 'Succès', detail: 'Email de test envoyé !' });
      },
      error: (err) => {
        this.testingEmail = false;
        const detail = err.error?.message || 'Erreur lors de l\'envoi du test';
        this.messageService.add({ severity: 'error', summary: 'Erreur SMTP', detail: detail });
      }
    });
  }

  testTeams() {
    if (!this.teamsSettings.webhookUrl) return;

    this.testingTeams = true;
    this.settingsService.sendTeamsTest(this.teamsSettings.webhookUrl).subscribe({
      next: () => {
        this.testingTeams = false;
        this.messageService.add({ severity: 'success', summary: 'Succès', detail: 'Message de test Teams envoyé !' });
      },
      error: (err) => {
        this.testingTeams = false;
        const detail = err.error?.message || 'Erreur lors de l\'envoi vers Teams';
        this.messageService.add({ severity: 'error', summary: 'Erreur Teams', detail: detail });
      }
    });
  }

  saveSettings() {
    this.saving = true;
    forkJoin({
      auth: this.settingsService.updateAuthSettings(this.authSettings),
      email: this.settingsService.updateEmailSettings(this.emailSettings),
      alert: this.settingsService.updateAlertSettings(this.alertSettings),
      teams: this.settingsService.updateTeamsSettings(this.teamsSettings)
    }).subscribe({
      next: (results) => {
        this.authSettings = { ...results.auth };
        this.originalAuth = { ...results.auth };

        this.emailSettings = { ...results.email };
        this.originalEmail = { ...results.email };

        this.alertSettings = { ...results.alert };
        this.originalAlert = { ...results.alert };

        this.teamsSettings = { ...results.teams };
        this.originalTeams = { ...results.teams };

        this.hasChanges = false;
        this.saving = false;
        this.messageService.add({ severity: 'success', summary: 'Succès', detail: 'Paramètres mis à jour' });
      },
      error: () => {
        this.saving = false;
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de mettre à jour les paramètres' });
      }
    });
  }
}
