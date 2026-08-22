import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    CataloguePreview,
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
    HistoryDossier,
    InventoryResults,
    IssueDetail,
    SignInMethods,
    TeamSummary,
    TeamTargetAssignment,
    OllamaCheck,
    OwaspReport,
    HistoryRepository,
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

    /**
     * Changes a repository. **Send only what changed.**
     *
     * Absent means unchanged and empty means cleared — sending the whole form back would erase
     * every field the form does not show, which is how an SSH key or a schedule disappears
     * without anybody touching it.
     */
    updateRepository(id: number, changes: Partial<NewRepository>): Observable<MonitoredRepository> {
        return this.http.patch<MonitoredRepository>(`/api/v1/repositories/${id}`, changes);
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

    webhookSecretState(): Observable<{ configured: boolean }> {
        return this.http.get<{ configured: boolean }>('/api/v1/settings/webhook-secret');
    }

    setWebhookSecret(secret: string): Observable<{ configured: boolean }> {
        return this.http.put<{ configured: boolean }>('/api/v1/settings/webhook-secret', { secret });
    }

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

    /**
     * Any document the server serves as a file.
     *
     * **Through `HttpClient`, never a navigation.** The token is in memory and travels only on
     * requests the interceptor sees; a browser navigation carries none, the server answers 401
     * and the browser saves the empty body as a zero-byte file.
     */
    issue(id: number): Observable<IssueDetail> {
        return this.http.get<IssueDetail>(`/api/v1/issues/${id}`);
    }

    signInMethods(): Observable<SignInMethods> {
        return this.http.get<SignInMethods>('/api/v1/auth/methods');
    }

    /**
     * Trades the one-time hand-off cookie for the session it stands for.
     *
     * <p>`withCredentials` is what makes it work: the cookie is host-only and would not be sent
     * otherwise, and the sign-on would succeed while the application still showed a login screen.
     */
    completeSignIn(): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/session/exchange', {}, { withCredentials: true });
    }

    downloadDocument(path: string): Observable<HttpResponse<Blob>> {
        return this.http.get(path, { responseType: 'blob', observe: 'response' });
    }

    owaspReport(repositoryId: number): Observable<OwaspReport> {
        return this.http.get<OwaspReport>(`/api/v1/repositories/${repositoryId}/owasp-review`);
    }

    runOwaspReport(repositoryId: number): Observable<OwaspReport> {
        return this.http.post<OwaspReport>(`/api/v1/repositories/${repositoryId}/owasp-review`, {});
    }

    testOllama(): Observable<OllamaCheck> {
        return this.http.post<OllamaCheck>('/api/v1/settings/ollama-test', {});
    }

    searchComponents(name: string, version: string): Observable<InventoryResults> {
        const params = new URLSearchParams({ name });
        if (version) {
            params.set('version', version);
        }
        return this.http.get<InventoryResults>(`/api/v1/inventory/search?${params.toString()}`);
    }

    historyRepositories(): Observable<HistoryRepository[]> {
        return this.http.get<HistoryRepository[]>('/api/v1/history/repositories');
    }

    historyDossier(id: number): Observable<HistoryDossier> {
        return this.http.get<HistoryDossier>(`/api/v1/history/repositories/${id}`);
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

    teamTargets(id: number): Observable<TeamTargetAssignment[]> {
        return this.http.get<TeamTargetAssignment[]>(`/api/v1/teams/${id}/targets`);
    }

    setTeamTargets(id: number, targets: TeamTargetAssignment[]): Observable<TeamTargetAssignment[]> {
        return this.http.put<TeamTargetAssignment[]>(`/api/v1/teams/${id}/targets`, targets);
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
