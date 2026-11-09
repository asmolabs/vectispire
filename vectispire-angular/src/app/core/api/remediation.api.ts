import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { RemediationDistribution, SecurityDebtReport, HighImpactFix, RemediationCoverage } from '../api.models';

/**
 * Remediation: the security debt, the plan ranked by leverage, what it cannot close, and how long
 * fixes take.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class RemediationApi {
    private readonly http = inject(HttpClient);

    getSecurityDebt(repoId?: number, containerId?: number): Observable<SecurityDebtReport> {
        let params = new HttpParams();
        if (repoId) params = params.set('repoId', repoId);
        if (containerId) params = params.set('containerId', containerId);
        return this.http.get<SecurityDebtReport>('/api/v1/remediation/debt', { params });
    }

    /**
     * The work order ranked by leverage.
     *
     * <p>`limit` is optional: without it the server returns ten, which is the right answer to
     * "where do I start". The screen passes it when somebody asks for more, and the server clamps
     * the value into its bounds rather than refusing.
     */
    getHighImpactFixes(repoId?: number, containerId?: number, limit?: number): Observable<HighImpactFix[]> {
        let params = new HttpParams();
        if (repoId) params = params.set('repoId', repoId);
        if (containerId) params = params.set('containerId', containerId);
        if (limit) params = params.set('limit', limit);
        return this.http.get<HighImpactFix[]>('/api/v1/remediation/high-impact-fixes', { params });
    }

    /**
     * What the plan cannot close, and of which family.
     *
     * Called separately from the plan: failing to get the admission does not prevent showing the
     * work order, which is the screen's subject.
     */
    getRemediationCoverage(repoId?: number, containerId?: number): Observable<RemediationCoverage> {
        let params = new HttpParams();
        if (repoId) params = params.set('repoId', repoId);
        if (containerId) params = params.set('containerId', containerId);
        return this.http.get<RemediationCoverage>('/api/v1/remediation/coverage', { params });
    }

    remediationDistribution(days?: number): Observable<RemediationDistribution> {
        let params = new HttpParams();
        if (days) params = params.set('days', days);
        return this.http.get<RemediationDistribution>('/api/v1/remediation/distribution', { params });
    }
}
