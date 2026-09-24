import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { RuleCoverageAssessment, CataloguePreview, RuleSetImpact, RuleSetSummary } from '../api.models';

/**
 * The SAST rule sets: the upstream catalogue, uploads, activation, and what the active set covers.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class RuleSetsApi {
    private readonly http = inject(HttpClient);

    /** What the upstream catalogue holds right now, and the licence text at that commit. */
    ruleCatalogue() {
        return this.http.get<CataloguePreview>('/api/v1/rule-sets/catalogue');
    }

    /**
     * Fetches the chosen languages. The digest is echoed back from the preview: it is what binds
     * the acceptance to a licence rather than to a button.
     */
    fetchRuleCatalogue(commit: string, languages: string[], licenceSha256: string) {
        return this.http.post<{ id: number; ruleCount: number; fileCount: number }>(
            '/api/v1/rule-sets/catalogue',
            { commit, languages, licence_sha256: licenceSha256 }
        );
    }

    ruleSets() {
        return this.http.get<{ ruleSets: RuleSetSummary[] }>('/api/v1/rule-sets');
    }

    uploadRuleSet(name: string, files: { name: string; content: string }[]) {
        return this.http.post<{ id: number; contentHash: string; ruleCount: number; fileCount: number }>('/api/v1/rule-sets', { name, files });
    }

    ruleSetImpact(id: number) {
        return this.http.get<RuleSetImpact>(`/api/v1/rule-sets/${id}/impact`);
    }

    activateRuleSet(id: number, note: string | null) {
        return this.http.post<{ id: number; contentHash: string }>(`/api/v1/rule-sets/${id}/activate`, { note });
    }

    deactivateRuleSets() {
        return this.http.post<{ active: null }>('/api/v1/rule-sets/deactivate', {});
    }

    ruleCoverage(): Observable<RuleCoverageAssessment> {
        return this.http.get<RuleCoverageAssessment>('/api/v1/rule-sets/coverage');
    }
}
