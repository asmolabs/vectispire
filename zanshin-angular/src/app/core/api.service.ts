import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    AgentSummary,
    ApiKeySummary,
    ApiKeyTargets,
    AuditEntry,
    AuditFilters,
    AuditVerification,
    DashboardOverview,
    Issue,
    RuleSetImpact,
    RuleSetSummary,
    IssueFilters,
    IssuedApiKey,
    LoginResponse,
    MonitoredContainer,
    MonitoredRepository,
    NewAgent,
    UnroutableLabel,
    NewApiKey,
    NewContainer,
    NewRepository,
    NewSshKey,
    NewUser,
    Page,
    QualityOverview,
    ScanDetail,
    SecurityOverview,
    SettingDefinition,
    SshKeySummary,
    TriageRequest,
    UserList,
    UserPatch,
    UserSummary
} from './api.models';

/**
 * Access to the API, in one place.
 *
 * One service per resource would be more usual; a single one is enough while the surface fits
 * on a screen, and it avoids multiplying files that do nothing but call `HttpClient`. To be
 * split the day it stops fitting.
 *
 * No absolute URL: the development server proxies `/api` to the backend
 * (`proxy.conf.json`), and in production both are served from the same origin — which is also
 * what lets the CSP stay on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class ApiService {
    private readonly http = inject(HttpClient);

    login(username: string, password: string, clientId: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/login', { username, password, client_id: clientId });
    }

    changePassword(currentPassword: string, newPassword: string): Observable<{ mustChangePassword: boolean }> {
        return this.http.post<{ mustChangePassword: boolean }>('/api/v1/auth/change-password', {
            current_password: currentPassword,
            new_password: newPassword
        });
    }

    logout(): Observable<void> {
        return this.http.delete<void>('/api/v1/auth/session');
    }

    issues(filters: IssueFilters = {}): Observable<Page<Issue>> {
        let params = new HttpParams();
        for (const [key, value] of Object.entries(filters)) {
            // An absent value must not become "undefined" in the URL — the server would read
            // it as a filter on the literal string "undefined".
            if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
        }
        return this.http.get<Page<Issue>>('/api/v1/issues', { params });
    }

    triage(issueId: number, request: TriageRequest): Observable<Issue> {
        return this.http.post<Issue>(`/api/v1/issues/${issueId}/triage`, request);
    }

    dashboard(): Observable<DashboardOverview> {
        return this.http.get<DashboardOverview>('/api/v1/dashboard');
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

    /**
     * An export, as bytes plus the response that carries its filename.
     *
     * **Not a plain `<a href>`**, which was the first attempt and answered 401 every time: the
     * session token lives in memory and is put on requests by the interceptor, so a browser
     * navigation carries no credential at all. Going through `HttpClient` is what authenticates
     * the download — and `observe: 'response'` is what keeps the server's filename, which the
     * body alone does not carry.
     */
    exportDocument(kind: string, id: number, document: string): Observable<HttpResponse<Blob>> {
        return this.http.get(`/api/v1/targets/${kind}/${id}/${document}`, {
            responseType: 'blob',
            observe: 'response'
        });
    }

    settings(): Observable<{ settings: SettingDefinition[] }> {
        return this.http.get<{ settings: SettingDefinition[] }>('/api/v1/settings');
    }

    updateSettings(values: Record<string, string>): Observable<{ updated: number }> {
        return this.http.put<{ updated: number }>('/api/v1/settings', values);
    }

    ticketTokenState(): Observable<{ configured: boolean }> {
        return this.http.get<{ configured: boolean }>('/api/v1/settings/ticket-token');
    }

    setTicketToken(token: string): Observable<{ configured: boolean }> {
        return this.http.put<{ configured: boolean }>('/api/v1/settings/ticket-token', { token });
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

    agents(): Observable<AgentSummary[]> {
        return this.http.get<AgentSummary[]>('/api/v1/admin/agents');
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

    setAgentEnabled(id: string, enabled: boolean): Observable<{ id: string; enabled: boolean }> {
        return this.http.patch<{ id: string; enabled: boolean }>(`/api/v1/admin/agents/${id}`, { enabled });
    }

    deleteAgent(id: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/admin/agents/${id}`);
    }

    scan(id: number): Observable<ScanDetail> {
        return this.http.get<ScanDetail>(`/api/v1/scans/${id}`);
    }

    triggerContainerScan(id: number): Observable<{ id: number; status: string }> {
        return this.http.post<{ id: number; status: string }>(`/api/v1/containers/${id}/scan`, {});
    }

    triggerRepositoryScan(id: number): Observable<{ id: number; status: string }> {
        return this.http.post<{ id: number; status: string }>(`/api/v1/repositories/${id}/scan`, {});
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

    auditLog(filters: AuditFilters = {}): Observable<Page<AuditEntry>> {
        let params = new HttpParams();
        for (const [key, value] of Object.entries(filters)) {
            if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
        }
        return this.http.get<Page<AuditEntry>>('/api/v1/audit-log', { params });
    }

    auditOperationTypes(): Observable<string[]> {
        return this.http.get<string[]>('/api/v1/audit-log/operation-types');
    }

    verifyAuditChain(): Observable<AuditVerification> {
        return this.http.get<AuditVerification>('/api/v1/audit-log/verify');
    }
}
