import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    GatePolicies,
    GatePolicy,
    GatePolicyRequest,
    CataloguePreview,
    AgentSummary,
    AgentActivitySummary,
    ApiKeySummary,
    ApiKeyTargets,
    AuditEntry,
    AuditFilters,
    AuditVerification,
    BulkTriageRequest,
    DashboardOverview,
    Trends,
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
    ComplianceSummary,
    ComplianceEvaluation,
    MfaSetupResponse,
    MfaEnableResponse,
    IssueTicket,
    InTotoAttestation,
    LicenseEntry,
    LicensePolicy,
    LicenseSummary,
    OpenVexDocument,
    SecurityGrade,
    SecurityScorecard,
    SiemConfig,
    SiemTestResult,
    ThreatIntelSyncStatus,
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

    /**
     * The same decision on every issue in the batch.
     *
     * All or nothing: the server checks every id before writing the first, so a refusal means
     * nothing was triaged. A caller that retried "the rest" after a failure would be inventing
     * a partial outcome the API does not produce.
     */
    triageMany(request: BulkTriageRequest): Observable<Issue[]> {
        return this.http.post<Issue[]>('/api/v1/issues/triage', request);
    }

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
        const path = scope.kind === 'global' ? '/api/v1/gate/policies/global' : `/api/v1/gate/policies/${scope.kind}/${scope.id}`;
        return this.http.put<GatePolicy>(path, policy);
    }

    /** Removes an override, so the target inherits the global policy again. */
    removeGatePolicy(kind: 'repository' | 'container', id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/gate/policies/${kind}/${id}`);
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

    /**
     * Changes a monitored image, the row and its scan history staying put.
     *
     * `Partial`, because the server reads an absent field as "leave alone": a screen that edits
     * two fields sends two fields. The one exception is the interval, where `null` is already
     * "leave alone" and switching a rescan off is spelled `0` — see `ContainersController.update`.
     */
    updateContainer(id: number, changes: Partial<NewContainer>): Observable<MonitoredContainer> {
        return this.http.patch<MonitoredContainer>(`/api/v1/containers/${id}`, changes);
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

    complianceSummary(): Observable<ComplianceSummary> {
        return this.http.get<ComplianceSummary>('/api/v1/compliance/summary');
    }

    complianceFramework(framework: string): Observable<ComplianceEvaluation> {
        return this.http.get<ComplianceEvaluation>(`/api/v1/compliance/frameworks/${framework}`);
    }

    exportCompliancePdf(): Observable<HttpResponse<Blob>> {
        return this.downloadDocument('/api/v1/compliance/export.pdf');
    }

    exportEvidenceBundle(): Observable<HttpResponse<Blob>> {
        return this.downloadDocument('/api/v1/compliance/evidence-bundle.zip');
    }

    verifyMfa(mfaToken: string, code: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>('/api/v1/auth/mfa/verify', { mfa_token: mfaToken, code });
    }

    setupMfa(): Observable<MfaSetupResponse> {
        return this.http.post<MfaSetupResponse>('/api/v1/auth/mfa/setup', {});
    }

    enableMfa(secret: string, code: string): Observable<MfaEnableResponse> {
        return this.http.post<MfaEnableResponse>('/api/v1/auth/mfa/enable', { secret, code });
    }

    disableMfa(code: string): Observable<{ mfaEnabled: boolean }> {
        return this.http.post<{ mfaEnabled: boolean }>('/api/v1/auth/mfa/disable', { code });
    }

    getIssueTickets(issueId: number): Observable<IssueTicket[]> {
        return this.http.get<IssueTicket[]>(`/api/v1/issues/${issueId}/tickets`);
    }

    createIssueTicket(issueId: number, payload: { provider: string; ticketKey: string; ticketUrl: string }): Observable<IssueTicket> {
        return this.http.post<IssueTicket>(`/api/v1/issues/${issueId}/tickets`, payload);
    }

    getScanAttestation(scanId: number): Observable<InTotoAttestation> {
        return this.http.get<InTotoAttestation>(`/api/v1/attestations/scans/${scanId}`);
    }

    getSiemConfig(): Observable<SiemConfig> {
        return this.http.get<SiemConfig>('/api/v1/siem/config');
    }

    updateSiemConfig(payload: { enabled: boolean; protocol: string; endpoint?: string; authHeader?: string; minSeverity: string }): Observable<SiemConfig> {
        return this.http.put<SiemConfig>('/api/v1/siem/config', payload);
    }

    testSiemConnection(payload: { endpoint: string; authHeader?: string }): Observable<SiemTestResult> {
        return this.http.post<SiemTestResult>('/api/v1/siem/test', payload);
    }

    getThreatIntelStatus(): Observable<ThreatIntelSyncStatus> {
        return this.http.get<ThreatIntelSyncStatus>('/api/v1/threat-intel/status');
    }

    syncThreatIntel(): Observable<ThreatIntelSyncStatus> {
        return this.http.post<ThreatIntelSyncStatus>('/api/v1/threat-intel/sync', {});
    }

    getScanVex(scanId: number): Observable<OpenVexDocument> {
        return this.http.get<OpenVexDocument>(`/api/v1/vex/scans/${scanId}/openvex.json`);
    }

    getAggregateVex(): Observable<OpenVexDocument> {
        return this.http.get<OpenVexDocument>('/api/v1/vex/aggregate.json');
    }

    getScanCsaf(scanId: number): Observable<unknown> {
        return this.http.get<unknown>(`/api/v1/csaf/scans/${scanId}/csaf.json`);
    }

    getAggregateCsaf(): Observable<unknown> {
        return this.http.get<unknown>('/api/v1/csaf/aggregate.json');
    }

    ingestVex(doc: OpenVexDocument): Observable<unknown> {
        return this.http.post<unknown>('/api/v1/vex/ingest', doc);
    }

    getLicenseSummary(repoId?: number, containerId?: number): Observable<LicenseSummary> {
        let params = new HttpParams();
        if (repoId) params = params.set('repo_id', repoId);
        if (containerId) params = params.set('container_id', containerId);
        return this.http.get<LicenseSummary>('/api/v1/licenses/summary', { params });
    }

    getLicenseInventory(repoId?: number, containerId?: number): Observable<LicenseEntry[]> {
        let params = new HttpParams();
        if (repoId) params = params.set('repo_id', repoId);
        if (containerId) params = params.set('container_id', containerId);
        return this.http.get<LicenseEntry[]>('/api/v1/licenses/inventory', { params });
    }

    getLicensePolicy(): Observable<LicensePolicy> {
        return this.http.get<LicensePolicy>('/api/v1/licenses/policy');
    }

    updateLicensePolicy(policy: LicensePolicy): Observable<LicensePolicy> {
        return this.http.put<LicensePolicy>('/api/v1/licenses/policy', policy);
    }

    getRepositoryScorecard(repoId: number): Observable<SecurityScorecard> {
        return this.http.get<SecurityScorecard>(`/api/v1/scorecards/repositories/${repoId}`);
    }

    getGlobalScorecard(): Observable<SecurityScorecard> {
        return this.http.get<SecurityScorecard>('/api/v1/scorecards/global');
    }
}
