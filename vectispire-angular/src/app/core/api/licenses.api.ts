import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { LicenseEntry, LicensePolicy, LicenseSummary, LicenseConflict, CompatibilityCell } from '../api.models';

/**
 * Licences: the summary, the inventory, the policy, conflicts and the compatibility matrix.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class LicensesApi {
    private readonly http = inject(HttpClient);

    getLicenseSummary(repoId?: number, containerId?: number): Observable<LicenseSummary> {
        let params = new HttpParams();
        if (repoId) params = params.set('repo_id', repoId);
        if (containerId) params = params.set('container_id', containerId);
        return this.http.get<LicenseSummary>('/api/v1/licenses/summary', { params });
    }

    getLicenseInventory(repoId?: number, containerId?: number): Observable<LicenseEntry[]> {
        let params = new HttpParams();
        if (repoId) params = params.set('repo_id', repoId);
        if (containerId) params = params.set('container_id', containerId);
        return this.http.get<LicenseEntry[]>('/api/v1/licenses/inventory', { params });
    }

    getLicensePolicy(): Observable<LicensePolicy> {
        return this.http.get<LicensePolicy>('/api/v1/licenses/policy');
    }

    updateLicensePolicy(policy: LicensePolicy): Observable<LicensePolicy> {
        return this.http.put<LicensePolicy>('/api/v1/licenses/policy', policy);
    }

    getLicenseConflicts(repoId?: number, containerId?: number, proprietary = true): Observable<LicenseConflict[]> {
        let params = new HttpParams().set('proprietary', proprietary);
        if (repoId) params = params.set('repo_id', repoId);
        if (containerId) params = params.set('container_id', containerId);
        return this.http.get<LicenseConflict[]>('/api/v1/licenses/conflicts', { params });
    }

    getLicenseCompatibilityMatrix(): Observable<CompatibilityCell[]> {
        return this.http.get<CompatibilityCell[]>('/api/v1/licenses/matrix');
    }
}
