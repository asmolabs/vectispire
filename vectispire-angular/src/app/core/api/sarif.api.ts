import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { SarifImport, SarifSource, SarifSourceDeclaration } from '../api.models';

/**
 * SARIF from declared internal sources (decision 0017 §7): the declarations, and what each
 * repository received.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 *
 * **There is no upload here, deliberately.** An import is accepted from a declared source's
 * integration key only — a session is not a source, and the server answers 403 to one. The
 * interface reads the history; the pipeline writes it.
 */
@Injectable({ providedIn: 'root' })
export class SarifApi {
    private readonly http = inject(HttpClient);

    /** Governance read. */
    sarifSources(): Observable<SarifSource[]> {
        return this.http.get<SarifSource[]>('/api/v1/sarif-sources');
    }

    /**
     * The platform governor's: "this producer is inside the organisation". Exactly one of
     * `project_id` and `repository_id`; the key must hold `sarif_import`.
     */
    declareSarifSource(declaration: SarifSourceDeclaration): Observable<SarifSource> {
        return this.http.post<SarifSource>('/api/v1/sarif-sources', declaration);
    }

    setSarifSourceEnabled(id: number, enabled: boolean): Observable<SarifSource> {
        return this.http.put<SarifSource>(`/api/v1/sarif-sources/${id}/enabled`, { enabled });
    }

    /** The issues it imported stay, and keep the source's slug as their provenance. */
    removeSarifSource(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/sarif-sources/${id}`);
    }

    /** The latest fifty. 404 for a repository the reader cannot see, as for one that does not exist. */
    sarifImports(repositoryId: number): Observable<SarifImport[]> {
        return this.http.get<SarifImport[]>(`/api/v1/repositories/${repositoryId}/sarif-imports`);
    }
}
