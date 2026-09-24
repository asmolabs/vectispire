import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { BadgeState, SecurityScorecard } from '../api.models';

/**
 * A repository's security scorecard and the public badge that may publish its grade.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class ScorecardsApi {
    private readonly http = inject(HttpClient);

    getRepositoryScorecard(repoId: number): Observable<SecurityScorecard> {
        return this.http.get<SecurityScorecard>(`/api/v1/scorecards/repositories/${repoId}`);
    }

    /**
     * Is this repository's grade published as a public badge, and under which URL?
     *
     * **Asked rather than assumed**, because a badge is now something somebody turns on. The old
     * screen built the badge URL from the repository's id and showed it unconditionally — which
     * was also how anybody could read any repository's grade by counting.
     */
    getRepositoryBadge(repoId: number): Observable<BadgeState> {
        return this.http.get<BadgeState>(`/api/v1/scorecards/repositories/${repoId}/badge`);
    }

    publishRepositoryBadge(repoId: number): Observable<BadgeState> {
        return this.http.post<BadgeState>(`/api/v1/scorecards/repositories/${repoId}/badge`, {});
    }

    revokeRepositoryBadge(repoId: number): Observable<BadgeState> {
        return this.http.delete<BadgeState>(`/api/v1/scorecards/repositories/${repoId}/badge`);
    }
}
