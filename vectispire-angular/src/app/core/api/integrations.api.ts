import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { SiemConfig, SiemTestResult, NotificationChannelStatus, NotificationTestResult } from '../api.models';

/**
 * Outbound integrations: the SIEM forwarder and the notification channels.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class IntegrationsApi {
    private readonly http = inject(HttpClient);

    getSiemConfig(): Observable<SiemConfig> {
        return this.http.get<SiemConfig>('/api/v1/siem/config');
    }

    updateSiemConfig(payload: {
        enabled: boolean;
        protocol: string;
        endpoint?: string;
        authHeader?: string;
        minSeverity: string;
    }): Observable<SiemConfig> {
        return this.http.put<SiemConfig>('/api/v1/siem/config', payload);
    }

    testSiemConnection(payload: { endpoint: string; authHeader?: string }): Observable<SiemTestResult> {
        return this.http.post<SiemTestResult>('/api/v1/siem/test', payload);
    }

    getNotificationChannels(): Observable<NotificationChannelStatus[]> {
        return this.http.get<NotificationChannelStatus[]>('/api/v1/notifications/channels');
    }

    testNotificationChannel(channelType: string): Observable<NotificationTestResult> {
        return this.http.post<NotificationTestResult>(
            `/api/v1/notifications/test/${encodeURIComponent(channelType)}`,
            {}
        );
    }
}
