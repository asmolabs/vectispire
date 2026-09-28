import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ThreatIntelSyncStatus, EpssFleetSummary, ThreatIntelRecord, AiVulnerabilityAdvice } from '../api.models';
import { SupportedLanguage } from '../i18n/i18n.service';

/**
 * Threat intelligence — the KEV and EPSS feeds — and the model that explains a vulnerability.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class IntelApi {
    private readonly http = inject(HttpClient);

    getThreatIntelStatus(): Observable<ThreatIntelSyncStatus> {
        return this.http.get<ThreatIntelSyncStatus>('/api/v1/threat-intel/status');
    }

    syncThreatIntel(): Observable<ThreatIntelSyncStatus> {
        return this.http.post<ThreatIntelSyncStatus>('/api/v1/threat-intel/sync', {});
    }

    getEpssPriorities(): Observable<EpssFleetSummary> {
        return this.http.get<EpssFleetSummary>('/api/v1/epss/priorities');
    }

    lookupEpssCve(cveId: string): Observable<ThreatIntelRecord> {
        return this.http.get<ThreatIntelRecord>(`/api/v1/epss/cve/${encodeURIComponent(cveId)}`);
    }

    syncEpss(): Observable<ThreatIntelSyncStatus> {
        return this.http.post<ThreatIntelSyncStatus>('/api/v1/epss/sync', {});
    }

    getAiAdvisorStatus(): Observable<{ enabled: boolean; selectedModel: string; availableModels: string[] }> {
        return this.http.get<{ enabled: boolean; selectedModel: string; availableModels: string[] }>(
            '/api/v1/ai-advisor/status'
        );
    }

    /**
     * `language` is the one the screen is shown in: the model is asked to answer in it. Nothing on
     * the server records a reader's language, so without it the answer is in English.
     */
    explainIssueWithAi(issueId: number, language: SupportedLanguage): Observable<AiVulnerabilityAdvice> {
        return this.http.post<AiVulnerabilityAdvice>(
            `/api/v1/ai-advisor/explain/issue/${issueId}`,
            {},
            { params: new HttpParams().set('language', language) }
        );
    }

    /**
     * The identifier alone: the route took a package, a version and a fix and printed them as the
     * advice's facts, and no longer reads them.
     */
    explainCveWithAi(cveId: string, language: SupportedLanguage): Observable<AiVulnerabilityAdvice> {
        return this.http.post<AiVulnerabilityAdvice>(
            `/api/v1/ai-advisor/explain/cve/${encodeURIComponent(cveId)}`,
            {},
            { params: new HttpParams().set('language', language) }
        );
    }
}
