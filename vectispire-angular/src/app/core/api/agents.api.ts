import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AgentSummary, AgentActivitySummary, NewAgent, UnroutableLabel, PinnedSigningKey } from '../api.models';

/**
 * The remote scan agents: enrolment, signing keys, activity and the labels nothing can route.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class AgentsApi {
    private readonly http = inject(HttpClient);

    agents(): Observable<AgentSummary[]> {
        return this.http.get<AgentSummary[]>('/api/v1/admin/agents');
    }

    getAgentActivity(): Observable<AgentActivitySummary> {
        return this.http.get<AgentActivitySummary>('/api/v1/admin/agents/activity');
    }

    /**
     * The labels demanded by targets that no enabled agent carries.
     *
     * Without this call, a mislabelled target queues scans that stay there for ever: the screen
     * says "queued", which is true and explains nothing.
     */
    unroutableLabels(): Observable<UnroutableLabel[]> {
        return this.http.get<UnroutableLabel[]>('/api/v1/admin/agents/non-routables');
    }

    createAgent(agent: NewAgent): Observable<{ id: string; name: string; secret: string }> {
        return this.http.post<{ id: string; name: string; secret: string }>('/api/v1/admin/agents', agent);
    }

    /**
     * Pins the key this agent's results must be signed with, or removes it.
     *
     * `'generate'` has the control plane make the pair and return the private half once; a
     * base64 public key pins one the operator generated themselves, which is the path where the
     * private half never existed here at all. An empty string removes the pin.
     */
    pinAgentSigningKey(id: string, publicKey: string): Observable<PinnedSigningKey> {
        return this.http.put<PinnedSigningKey>(`/api/v1/admin/agents/${id}/signing-key`, { public_key: publicKey });
    }

    /**
     * How many scans this agent may run at once, 1 to 16 — refused with a 400 outside that.
     *
     * Applies to the agent's next claim: scans already running are left to finish, even when the
     * new limit is below how many it holds.
     */
    setAgentMaxConcurrent(id: string, maxConcurrent: number): Observable<{ id: string }> {
        return this.http.patch<{ id: string }>(`/api/v1/admin/agents/${id}`, { max_concurrent: maxConcurrent });
    }

    setAgentEnabled(id: string, enabled: boolean): Observable<{ id: string; enabled: boolean }> {
        return this.http.patch<{ id: string; enabled: boolean }>(`/api/v1/admin/agents/${id}`, { enabled });
    }

    deleteAgent(id: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/admin/agents/${id}`);
    }
}
