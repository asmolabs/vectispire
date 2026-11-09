import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { DashboardOverview, Trends, QualityOverview, SecurityOverview, PostureTrendAnalytics } from '../api.models';

/**
 * The overviews: the dashboard, its trends and posture analytics, the security and quality
 * summaries.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class DashboardApi {
    private readonly http = inject(HttpClient);

    dashboard(): Observable<DashboardOverview> {
        return this.http.get<DashboardOverview>('/api/v1/dashboard');
    }

    /** The backlog over time. `days` is clamped server-side to 1..365, so no check here would
     *  add anything but a second opinion about the ceiling. */
    trends(days: number): Observable<Trends> {
        return this.http.get<Trends>('/api/v1/dashboard/trends', { params: new HttpParams().set('days', days) });
    }

    securityOverview(): Observable<SecurityOverview> {
        return this.http.get<SecurityOverview>('/api/v1/security/overview');
    }

    qualityOverview(): Observable<QualityOverview> {
        return this.http.get<QualityOverview>('/api/v1/quality/overview');
    }

    getPostureAnalytics(days = 30): Observable<PostureTrendAnalytics> {
        const params = new HttpParams().set('days', days);
        return this.http.get<PostureTrendAnalytics>('/api/v1/dashboard/posture-analytics', { params });
    }
}
