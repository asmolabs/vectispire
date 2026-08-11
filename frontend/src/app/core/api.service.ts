import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { Issue, IssueFilters, LoginResponse, Page, QualityOverview, SecurityOverview, TriageRequest ,
    MonitoredContainer,
    MonitoredRepository,
    NewContainer,
    NewSshKey,
    SshKeySummary,
    NewRepository} from './api.models';

/**
 * L'accès à l'API, en un point unique.
 *
 * Un service par ressource serait plus habituel ; un seul suffit tant que la surface
 * tient sur un écran, et évite de multiplier les fichiers qui ne font qu'appeler
 * `HttpClient`. À découper le jour où il ne tient plus.
 *
 * Aucune URL absolue : le serveur de développement relaie `/api` vers le backend
 * (`proxy.conf.json`), et en production les deux sont servis depuis la même origine —
 * ce qui est aussi ce qui permet à la CSP de rester en `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class ApiService {
    private readonly http = inject(HttpClient);

    login(username: string, password: string, clientId: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/login', { username, password, client_id: clientId });
    }

    logout(): Observable<void> {
        return this.http.delete<void>('/api/v1/auth/session');
    }

    issues(filters: IssueFilters = {}): Observable<Page<Issue>> {
        let params = new HttpParams();
        for (const [key, value] of Object.entries(filters)) {
            // Une valeur absente ne doit pas devenir « undefined » dans l'URL — le
            // serveur la lirait comme un filtre sur la chaîne « undefined ».
            if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
        }
        return this.http.get<Page<Issue>>('/api/v1/issues', { params });
    }

    triage(issueId: number, request: TriageRequest): Observable<Issue> {
        return this.http.post<Issue>(`/api/v1/issues/${issueId}/triage`, request);
    }

    securityOverview(): Observable<SecurityOverview> {
        return this.http.get<SecurityOverview>('/api/v1/security/overview');
    }

    qualityOverview(): Observable<QualityOverview> {
        return this.http.get<QualityOverview>('/api/v1/quality/overview');
    }

    repositories(): Observable<MonitoredRepository[]> {
        return this.http.get<MonitoredRepository[]>('/api/v1/repositories');
    }

    createRepository(repository: NewRepository): Observable<MonitoredRepository> {
        return this.http.post<MonitoredRepository>('/api/v1/repositories', repository);
    }

    deleteRepository(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/repositories/${id}`);
    }

    containers(): Observable<MonitoredContainer[]> {
        return this.http.get<MonitoredContainer[]>('/api/v1/containers');
    }

    createContainer(container: NewContainer): Observable<MonitoredContainer> {
        return this.http.post<MonitoredContainer>('/api/v1/containers', container);
    }

    deleteContainer(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/containers/${id}`);
    }

    sshKeys(): Observable<SshKeySummary[]> {
        return this.http.get<SshKeySummary[]>('/api/v1/ssh-keys');
    }

    createSshKey(key: NewSshKey): Observable<{ id: string }> {
        return this.http.post<{ id: string }>('/api/v1/ssh-keys', key);
    }

    deleteSshKey(id: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/ssh-keys/${id}`);
    }
}
