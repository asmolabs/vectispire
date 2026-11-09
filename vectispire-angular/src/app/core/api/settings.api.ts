import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map } from 'rxjs';
import { OllamaCheck, SettingDefinition, TicketCaState, TicketTokenState } from '../api.models';

/**
 * The instance settings under `/api/v1/settings`, including the write-only secrets and the model
 * check.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class SettingsApi {
    private readonly http = inject(HttpClient);

    settings(): Observable<{ settings: SettingDefinition[] }> {
        return this.http.get<{ settings: SettingDefinition[] }>('/api/v1/settings');
    }

    /**
     * The installation's default rescan interval in minutes — zero when there is none, `null` when the
     * catalogue does not carry it — for the schedule dialogs to say how often "nothing set" runs.
     */
    defaultScanIntervalMinutes(): Observable<number | null> {
        return this.settings().pipe(
            map((catalog) => {
                const days = Number(
                    catalog?.settings?.find((setting) => setting.key === 'scan_default_interval_days')?.value
                );
                return Number.isFinite(days) && days >= 0 ? days * 24 * 60 : null;
            })
        );
    }

    updateSettings(values: Record<string, string>): Observable<{ updated: number }> {
        return this.http.put<{ updated: number }>('/api/v1/settings', values);
    }

    /** Whether a token is stored, when it expires and whether the tracker refuses it. Never the token. */
    ticketTokenState(): Observable<TicketTokenState> {
        return this.http.get<TicketTokenState>('/api/v1/settings/ticket-token');
    }

    /** Stores the token; the answer is what the tracker said of it when asked right after. */
    setTicketToken(token: string): Observable<TicketTokenState> {
        return this.http.put<TicketTokenState>('/api/v1/settings/ticket-token', { token });
    }

    /**
     * What the tracker CA pins — subject and expiry, as a forge connection shows its CA. Administrator-only:
     * the value is written through {@link updateSettings} as `ticket_ca_pem`.
     */
    ticketCaState(): Observable<TicketCaState> {
        return this.http.get<TicketCaState>('/api/v1/settings/ticket-ca');
    }

    webhookSecretState(): Observable<{ configured: boolean }> {
        return this.http.get<{ configured: boolean }>('/api/v1/settings/webhook-secret');
    }

    setWebhookSecret(secret: string): Observable<{ configured: boolean }> {
        return this.http.put<{ configured: boolean }>('/api/v1/settings/webhook-secret', { secret });
    }

    /** Whether the inbound webhook secret is set. The secret itself is never returned. */
    ticketWebhookSecretState(): Observable<{ configured: boolean }> {
        return this.http.get<{ configured: boolean }>('/api/v1/settings/ticket-webhook-secret');
    }

    setTicketWebhookSecret(secret: string): Observable<{ configured: boolean }> {
        return this.http.put<{ configured: boolean }>('/api/v1/settings/ticket-webhook-secret', { secret });
    }

    /** Whether an API key is stored for the model provider. The key itself is never returned. */
    openAiKeyState(): Observable<{ configured: boolean }> {
        return this.http.get<{ configured: boolean }>('/api/v1/settings/ai-openai-key');
    }

    setOpenAiKey(secret: string): Observable<{ configured: boolean }> {
        return this.http.put<{ configured: boolean }>('/api/v1/settings/ai-openai-key', { secret });
    }

    testOllama(): Observable<OllamaCheck> {
        return this.http.post<OllamaCheck>('/api/v1/settings/ollama-test', {});
    }
}
