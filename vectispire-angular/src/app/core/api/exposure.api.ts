import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    BlastRadiusReport,
    TopImpactPackage,
    GlobalAttackSurface,
    RepositoryApisOverview,
    AttackPathGraph
} from '../api.models';

/**
 * What an attacker could reach: the attack surface, the APIs a repository exposes, attack paths
 * and the blast radius of a package.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class ExposureApi {
    private readonly http = inject(HttpClient);

    exploreBlastRadius(query?: string): Observable<BlastRadiusReport> {
        let params = new HttpParams();
        if (query) params = params.set('q', query);
        return this.http.get<BlastRadiusReport>('/api/v1/blast-radius/explore', { params });
    }

    getTopBlastRadius(limit = 10): Observable<TopImpactPackage[]> {
        const params = new HttpParams().set('limit', limit);
        return this.http.get<TopImpactPackage[]>('/api/v1/blast-radius/top-impact', { params });
    }

    getAttackSurface(): Observable<GlobalAttackSurface> {
        return this.http.get<GlobalAttackSurface>('/api/v1/attack-surface');
    }

    clearAttackSurface(): Observable<void> {
        return this.http.delete<void>('/api/v1/attack-surface');
    }

    getRepositoryApis(repositoryId: number): Observable<RepositoryApisOverview> {
        return this.http.get<RepositoryApisOverview>(`/api/v1/repositories/${repositoryId}/apis`);
    }

    clearRepositoryApis(repositoryId: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/repositories/${repositoryId}/apis`);
    }

    exportSynthesizedOpenApi(repositoryId: number): Observable<HttpResponse<Blob>> {
        return this.http.get(`/api/v1/repositories/${repositoryId}/apis/export/openapi`, {
            observe: 'response',
            responseType: 'blob'
        });
    }

    getAttackPathGraph(repoId: number): Observable<AttackPathGraph> {
        return this.http.get<AttackPathGraph>(`/api/v1/attack-paths/repositories/${repoId}`);
    }

    getAttackPathsOverview(): Observable<AttackPathGraph[]> {
        return this.http.get<AttackPathGraph[]>('/api/v1/attack-paths/overview');
    }
}
