import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { VerdictRegister, GatePolicies, GatePolicy, GatePolicyRequest } from '../api.models';

/**
 * The release gate: its policies and the register of its verdicts.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class GateApi {
    private readonly http = inject(HttpClient);

    gatePolicies(): Observable<GatePolicies> {
        return this.http.get<GatePolicies>('/api/v1/gate/policies');
    }

    /**
     * Stores the global policy, or one target's override.
     *
     * `PUT` rather than `PATCH` because the server replaces the policy whole: sending four
     * flags out of five would leave the fifth to a default, and "leave this alone" and "set it
     * to false" differ by a build that fails.
     */
    saveGatePolicy(
        scope: { kind: 'global' | 'repository' | 'container'; id: number | null },
        policy: GatePolicyRequest
    ): Observable<GatePolicy> {
        const path =
            scope.kind === 'global'
                ? '/api/v1/gate/policies/global'
                : `/api/v1/gate/policies/${scope.kind}/${scope.id}`;
        return this.http.put<GatePolicy>(path, policy);
    }

    /** Removes an override, so the target inherits the global policy again. */
    removeGatePolicy(kind: 'repository' | 'container', id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/gate/policies/${kind}/${id}`);
    }

    /**
     * The gate's answers, newest first.
     *
     * The server bounds `limit` itself; the screen does not validate it a second time, otherwise
     * the two bounds drift and it is the client's that gets forgotten.
     */
    gateVerdicts(limit?: number, cursor?: string | null): Observable<VerdictRegister> {
        let params = new HttpParams();
        if (limit) params = params.set('limit', limit);
        if (cursor) params = params.set('cursor', cursor);
        return this.http.get<VerdictRegister>('/api/v1/gate/verdicts', { params });
    }
}
