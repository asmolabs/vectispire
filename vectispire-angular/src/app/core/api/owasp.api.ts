import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    ControlDeclaration,
    DeclarationRequest,
    OwaspGrid,
    OwaspReport,
    OwaspScopeQuery,
    OwaspWeeklyCoverage,
    OwaspWeeklyQuery
} from '../api.models';

/**
 * OWASP: the fleet-wide coverage grid and its declarations, and one repository's review.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class OwaspApi {
    private readonly http = inject(HttpClient);

    owaspReport(repositoryId: number): Observable<OwaspReport> {
        return this.http.get<OwaspReport>(`/api/v1/repositories/${repositoryId}/owasp-review`);
    }

    runOwaspReport(repositoryId: number): Observable<OwaspReport> {
        return this.http.post<OwaspReport>(`/api/v1/repositories/${repositoryId}/owasp-review`, {});
    }

    /**
     * States what a category becomes when no scanner here measures it.
     *
     * The body is the statement of applicability's — same rules, and they name no framework in
     * particular: a declaration must say what it asserts and where its evidence lives.
     */
    declareOwaspCategory(category: string, body: DeclarationRequest): Observable<ControlDeclaration> {
        return this.http.put<ControlDeclaration>(`/api/v1/owasp/coverage/${category}/declaration`, body);
    }

    /**
     * The grid as it stands, over the reader's estate or one project or solution. Nothing is sent
     * for the estate: a request without parameters is the estate's, as it was before scopes existed.
     */
    owaspCoverage(query: OwaspScopeQuery = {}): Observable<OwaspGrid> {
        return this.http.get<OwaspGrid>('/api/v1/owasp/coverage', { params: paramsOf(query) });
    }

    /**
     * The grid week by week, over the reader's estate or one project or solution.
     *
     * Only what is set is sent: the server's defaults — the last twelve weeks, ending with the
     * current one — are the server's, and restating them here would be a second copy to drift.
     */
    weeklyCoverage(query: OwaspWeeklyQuery = {}): Observable<OwaspWeeklyCoverage> {
        return this.http.get<OwaspWeeklyCoverage>('/api/v1/owasp/coverage/weekly', { params: paramsOf(query) });
    }
}

/** Only what is set: an empty value sent as `?project_id=` would be a 400 for a question nobody asked. */
function paramsOf(query: OwaspWeeklyQuery): HttpParams {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
    }
    return params;
}
