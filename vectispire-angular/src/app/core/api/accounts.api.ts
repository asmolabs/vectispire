import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    ApiKeySummary,
    ApiKeyTargets,
    IssuedApiKey,
    NewApiKey,
    NewUser,
    TeamSummary,
    TeamTargetAssignment,
    UserTargetAssignment,
    UserList,
    UserPatch,
    UserSummary
} from '../api.models';

/**
 * Who can call and what they see: users, teams, API keys, and the targets each is granted.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class AccountsApi {
    private readonly http = inject(HttpClient);

    users(): Observable<UserList> {
        return this.http.get<UserList>('/api/v1/users');
    }

    createUser(user: NewUser): Observable<UserSummary> {
        return this.http.post<UserSummary>('/api/v1/users', user);
    }

    updateUser(id: number, patch: UserPatch): Observable<UserSummary> {
        return this.http.patch<UserSummary>(`/api/v1/users/${id}`, patch);
    }

    deleteUser(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/users/${id}`);
    }

    apiKeys(): Observable<ApiKeySummary[]> {
        return this.http.get<ApiKeySummary[]>('/api/v1/api-keys');
    }

    apiKeyTargets(): Observable<ApiKeyTargets> {
        return this.http.get<ApiKeyTargets>('/api/v1/api-keys/targets');
    }

    createApiKey(key: NewApiKey): Observable<IssuedApiKey> {
        return this.http.post<IssuedApiKey>('/api/v1/api-keys', key);
    }

    deleteApiKey(id: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/api-keys/${id}`);
    }

    teams(): Observable<TeamSummary[]> {
        return this.http.get<TeamSummary[]>('/api/v1/teams');
    }

    createTeam(team: { name: string; description?: string | null }): Observable<TeamSummary> {
        return this.http.post<TeamSummary>('/api/v1/teams', team);
    }

    updateTeam(id: number, patch: { name?: string; description?: string | null }): Observable<TeamSummary> {
        return this.http.patch<TeamSummary>(`/api/v1/teams/${id}`, patch);
    }

    deleteTeam(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/teams/${id}`);
    }

    /** Write-only: there is no companion getter, because nothing returns the URL. Empty removes
     *  the channel, and the team falls back to the global webhook. */
    setTeamWebhook(id: number, url: string): Observable<TeamSummary> {
        return this.http.put<TeamSummary>(`/api/v1/teams/${id}/webhook`, { url });
    }

    teamMembers(id: number): Observable<number[]> {
        return this.http.get<number[]>(`/api/v1/teams/${id}/members`);
    }

    /** Replaced wholesale: a server that only added would make a removal silently do nothing. */
    setTeamMembers(id: number, userIds: number[]): Observable<number[]> {
        return this.http.put<number[]>(`/api/v1/teams/${id}/members`, userIds);
    }

    /** Les cibles qu'un compte voit directement. Vide veut dire « aucune », en mode restreint. */
    userTargets(id: number): Observable<UserTargetAssignment[]> {
        return this.http.get<UserTargetAssignment[]>(`/api/v1/users/${id}/targets`);
    }

    /**
     * Replaces the whole set at once.
     *
     * <p>Wholesale and not by additions: the operation that matters is the <em>removal</em>, and a
     * screen sending only what it wants added would make a revocation a click with no effect.
     */
    setUserTargets(id: number, targets: UserTargetAssignment[]): Observable<UserTargetAssignment[]> {
        return this.http.put<UserTargetAssignment[]>(`/api/v1/users/${id}/targets`, targets);
    }

    teamTargets(id: number): Observable<TeamTargetAssignment[]> {
        return this.http.get<TeamTargetAssignment[]>(`/api/v1/teams/${id}/targets`);
    }

    setTeamTargets(id: number, targets: TeamTargetAssignment[]): Observable<TeamTargetAssignment[]> {
        return this.http.put<TeamTargetAssignment[]>(`/api/v1/teams/${id}/targets`, targets);
    }
}
