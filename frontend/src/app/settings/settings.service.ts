import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

export interface AuthSettings {
  githubEnabled: boolean;
  keycloakEnabled: boolean;
}

export interface EmailSettings {
  smtpHost: string;
  smtpPort: string;
  smtpUser: string;
  smtpPass: string;
  smtpFrom: string;
}

export interface AlertSettings {
  alertEmails: string;
  alertMinSeverity: string;
}

export interface TeamsSettings {
  webhookUrl: string;
  enabled: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class SettingsService {
  private http = inject(HttpClient);
  private baseUrl = 'http://localhost:3000/settings';

  getAuthSettings() {
    return this.http.get<AuthSettings>(`${this.baseUrl}/auth`);
  }

  updateAuthSettings(settings: Partial<AuthSettings>) {
    return this.http.put<AuthSettings>(`${this.baseUrl}/auth`, settings);
  }

  getEmailSettings() {
    return this.http.get<EmailSettings>(`${this.baseUrl}/email`);
  }

  updateEmailSettings(settings: Partial<EmailSettings>) {
    return this.http.put<EmailSettings>(`${this.baseUrl}/email`, settings);
  }

  getAlertSettings() {
    return this.http.get<AlertSettings>(`${this.baseUrl}/alerting`);
  }

  updateAlertSettings(settings: Partial<AlertSettings>) {
    return this.http.put<AlertSettings>(`${this.baseUrl}/alerting`, settings);
  }

  sendTestEmail(email: string) {
    return this.http.post(`${this.baseUrl}/email/test`, { email });
  }

  getTeamsSettings() {
    return this.http.get<TeamsSettings>(`${this.baseUrl}/teams`);
  }

  updateTeamsSettings(settings: Partial<TeamsSettings>) {
    return this.http.put<TeamsSettings>(`${this.baseUrl}/teams`, settings);
  }

  sendTeamsTest(webhookUrl: string) {
    return this.http.post(`${this.baseUrl}/teams/test`, { webhookUrl });
  }
}
