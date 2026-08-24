/**
 * The shapes the API returns.
 *
 * **Hand-written, and not yet replaceable.** `npm run generate:api` does produce
 * `api.generated.ts` from `/api/v1/openapi.json`, but that document today describes only the
 * *paths*: NestJS declares a response schema only where the controller carries the
 * `@ApiResponse`/`@ApiOkResponse` decorators and returns a DTO class. Without them the
 * generator emits operations with empty responses — useful for the URLs, silent on the shapes.
 *
 * This file will therefore disappear when the controllers have their DTOs, and not before. It
 * holds shapes only, no logic, so that removing it then costs nothing.
 */

export interface AuthenticatedUser {
    username: string;
    displayName: string | null;
    role: string;
    mustChangePassword: boolean;
    mfaEnabled?: boolean;
}

export interface LoginResponse {
    token?: string;
    expiresAt?: string;
    user?: AuthenticatedUser;
    mfa_required?: boolean;
    mfa_token?: string;
}

export interface MfaSetupResponse {
    secret: string;
    qrCodeUri: string;
    issuer: string;
}

export interface MfaEnableResponse {
    success: boolean;
    backupCodes: string[];
}

export interface IssueTicket {
    id: number;
    issueId: number;
    provider: 'JIRA' | 'GITHUB' | 'GITLAB';
    ticketKey: string;
    ticketUrl: string;
    status: string;
    createdAt: string;
    updatedAt: string;
}

export interface SiemConfig {
    enabled: boolean;
    protocol: 'WEBHOOK' | 'SYSLOG_UDP' | 'SYSLOG_TCP' | 'SYSLOG_TLS';
    endpoint: string | null;
    hasAuthHeader: boolean;
    minSeverity: string;
    updatedAt: string | null;
    authHeader?: string;
}

export interface SiemTestResult {
    success: boolean;
    message: string;
    statusCode: number;
}

export interface ThreatIntelSyncStatus {
    lastSyncedAt: string | null;
    totalCves: number;
    totalKev: number;
    status: string;
    backlogUpdatedCount: number;
}

export interface OpenVexStatement {
    vulnerability: { name: string };
    products: string[];
    status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
    justification?: 'component_not_present' | 'vulnerable_code_not_present' | 'vulnerable_code_not_in_execute_path' | 'vulnerable_code_cannot_be_controlled_by_adversary' | 'inline_mitigations_exist';
    impact_statement?: string;
    action_statement?: string;
    status_notes?: string;
}

export interface OpenVexDocument {
    '@context': string;
    '@id': string;
    author: string;
    role: string;
    timestamp: string;
    version: number;
    tooling: string;
    statements: OpenVexStatement[];
}

export type LicenseRiskCategory = 'PERMISSIVE' | 'WEAK_COPYLEFT' | 'STRONG_COPYLEFT' | 'FORBIDDEN' | 'UNKNOWN';

export interface LicenseEntry {
    packageName: string;
    packageVersion: string;
    purl: string | null;
    license: string;
    riskCategory: LicenseRiskCategory;
    compliant: boolean;
    violationReason: string | null;
    targetId: number | null;
    targetKind: string;
    targetName: string;
}

export interface LicensePolicy {
    disallowedCategories: LicenseRiskCategory[];
    explicitlyAllowedLicenses: string[];
    explicitlyDisallowedLicenses: string[];
}

export interface LicenseSummary {
    totalDependencies: number;
    uniqueLicenses: number;
    nonCompliantCount: number;
    breakdownByRisk: Record<LicenseRiskCategory, number>;
}

export type SecurityGrade = 'A_PLUS' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface SecurityScorecard {
    targetId: number | null;
    targetKind: string;
    targetName: string;
    score: number;
    grade: SecurityGrade;
    openCriticalCount: number;
    openHighCount: number;
    openKevCount: number;
    overdueCount: number;
    licenseViolationCount: number;
    hasAttestation: boolean;
    recommendations: string[];
}

export interface InTotoAttestation {
    _type: string;
    subject: { name: string; digest: Record<string, string> }[];
    predicateType: string;
    predicate: {
        builder: { id: string; version: string };
        invocation: {
            scanId: number;
            targetKind: string;
            targetName: string;
            branch: string;
            commitSha: string | null;
            timestamp: string;
        };
        policy: {
            gatePassed: boolean;
            violations: string[];
            enforcedPolicy: string;
        };
        findings: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            total: number;
        };
        sbomDigestSha256: string | null;
    };
}

export interface Issue {
    id: number;
    repoId: number | null;
    containerId: number | null;
    /** Resolved by the server, so one target is never named two things on two screens. */
    targetKind: 'repository' | 'container';
    targetName: string | null;
    type: string;
    identifier: string | null;
    severity: string | null;
    packageName: string | null;
    packageVersion: string | null;
    purl: string | null;
    filePath: string | null;
    line: number | null;
    cvssScore: number | null;
    epssScore: number | null;
    isKev: boolean;
    fixState: string | null;
    fixVersions: string | null;
    link: string | null;
    description: string | null;
    state: string;
    firstSeenAt: string;
    lastSeenAt: string;
    timesSeen: number;
    triageStatus: string;
    triageJustification: string | null;
    triageComment: string | null;
    triagedBy: string | null;
    triagedAt: string | null;
    triageExpiresAt: string | null;
    isDirectDependency: boolean | null;
    ticketRef: string | null;
    ticketUrl: string | null;
    reachability?: 'REACHABLE' | 'UNREACHABLE' | 'UNKNOWN';
    reachableSymbols?: string | null;
    /** When this issue's remediation window closes; null when none applies — a severity with no
     *  window, or an issue already settled or closed.
     *
     *  **Computed by the server**, like the gate verdict. Deriving it here from the policy would
     *  be a second implementation of the deadline, and the two would disagree the day it moves. */
    slaDueAt: string | null;
    /** `on_time`, `due_soon` or `overdue`; null with no deadline. A state and not a date to
     *  compare, so "late" means the same thing on this screen, in an export and in a report. */
    slaState: 'on_time' | 'due_soon' | 'overdue' | null;
    /** Days until due, **negative when late**. One signed field: "3 days late" and "due in 12
     *  days" are one measurement read from opposite sides. */
    slaDays: number | null;
}

export interface Page<T> {
    items: T[];
    total: number;
    limit: number;
    offset: number;
}

export interface IssueFilters {
    state?: string;
    severity?: string;
    type?: string;
    is_kev?: boolean;
    /** Open, not settled, and past the window its severity carries. The server owns the
     *  thresholds: sending dates from here would be a second copy of the policy. */
    overdue?: boolean;
    triage_status?: string;
    repository_id?: number;
    container_id?: number;
    only_direct?: boolean;
    search?: string;
    limit?: number;
    offset?: number;
}

export interface TriageRequest {
    status: string;
    justification?: string | null;
    comment?: string | null;
    expires_in_days?: number | null;
}

/**
 * The same decision on many issues.
 *
 * Its own type rather than `TriageRequest & { ids }`: the single-issue route would then accept an
 * `ids` field it silently ignores, which is the mistake the API deliberately avoided by keeping
 * two records.
 */
export interface BulkTriageRequest extends TriageRequest {
    /** At most 500 — the server refuses a longer batch rather than truncating it. */
    ids: number[];
}

export interface GateViolation {
    rule: 'kev' | 'severity';
    issueId: number;
    identifier: string | null;
    severity: string;
    package: string | null;
    fixVersions: string | null;
    reason: string;
}

export interface ResolvedGatePolicy {
    failOnSeverity: string | null;
    failOnKev: boolean;
    fixableOnly: boolean;
    includeTriaged: boolean;
    includeAiReview: boolean;
    source: 'target' | 'global' | 'built-in';
    version: number | null;
    description: string;
}

/** What the last scan says about how far the verdict can be trusted. */
export type Observation = 'ok' | 'never_scanned' | 'last_scan_failed' | 'in_progress';

export interface TargetPosture {
    kind: 'repository' | 'container';
    targetId: number;
    name: string;
    verdict: { passed: boolean; evaluated: number; violations: GateViolation[]; countsBySeverity: Record<string, number> };
    policy: { source: string; version: number | null };
    observation: Observation;
    lastScanAt: string | null;
    lastScanId: number | null;
    passed: boolean;
    /**
     * Does the verdict rest on a real observation? A target that was never scanned produces an
     * empty backlog, and an empty backlog passes every policy.
     */
    observed: boolean;
}

export interface SecurityOverview {
    targets: TargetPosture[];
    failingCount: number;
    totalCount: number;
    kevCount: number;
    neverScannedCount: number;
    lastScanFailedCount: number;
}

/** A grouped count — a rule, a file or a repository, and how many findings it carries. */
export interface Tally {
    label: string | null;
    count: number;
}

export interface QualityOverview {
    openCount: number;
    ruleCount: number;
    fileCount: number;
    topRules: Tally[];
    topFiles: Tally[];
    topTargets: Tally[];
}

export type AssetTier = 'TIER_1_MISSION_CRITICAL' | 'TIER_2_BUSINESS_OPERATIONAL' | 'TIER_3_INTERNAL';

/** A monitored repository, with the state of its last scan. */
export interface MonitoredRepository {
    id: number;
    url: string;
    branch: string;
    name: string | null;
    /** Computed by the server, so the same repository carries the same name everywhere. */
    displayName: string;
    subPath: string | null;
    scanIntervalMinutes: number | null;
    scanCron: string | null;
    /** The label an agent must carry to scan this target. Sent by the server all along. */
    requiredAgentLabel: string | null;
    sshKeyId: string | null;
    lastScan: { id: number; status: string; createdAt: string | null; error: string | null } | null;
    openIssues: number;
    tier?: AssetTier;
}

export interface NewRepository {
    url: string;
    branch: string;
    name?: string;
    subPath?: string;
    scanIntervalMinutes?: number | null;
    scanCron?: string;
    required_agent_label?: string;
    tier?: AssetTier;
}

/** The state of a last scan, shared by repositories and containers. */
export interface LastScan {
    id: number;
    status: string;
    createdAt: string | null;
    error: string | null;
}

/** A monitored container image. */
export interface MonitoredContainer {
    id: number;
    registry: string | null;
    imageName: string;
    tag: string;
    /** Computed by the server: the form a registry expects. */
    reference: string;
    scanIntervalMinutes: number | null;
    scanCron: string | null;
    requiredAgentLabel: string | null;
    lastScan: LastScan | null;
    openIssues: number;
    tier?: AssetTier;
}

export interface NewContainer {
    registry?: string;
    image_name: string;
    tag: string;
    scanIntervalMinutes?: number | null;
    scanCron?: string;
    required_agent_label?: string;
    tier?: AssetTier;
}

/** Where a private key stands with respect to the configured encryption keys. */
export type EncryptionState = 'current' | 'previous_key' | 'unreadable';

/** A deployment key. The private half never appears here: the server does not return it, and
 *  no screen would have a reason to show it. */
export interface SshKeySummary {
    id: string;
    name: string;
    publicKey: string | null;
    createdAt: string;
    encryptionState: EncryptionState;
    usedByRepositories: number;
}

export interface NewSshKey {
    name: string;
    private_key: string;
    public_key?: string;
}

/** An account. The password hash never appears here: the server does not return it, and a
 *  bcrypt hash that leaves the server is a hash to be cracked. */
export interface UserSummary {
    id: number;
    username: string;
    email: string | null;
    displayName: string | null;
    role: string;
    isActive: boolean;
    mustChangePassword: boolean;
    createdAt: string;
    activeSessions: number;
}

export interface UserList {
    users: UserSummary[];
    /** So the screen does not offer actions the server will refuse anyway. */
    currentUserId: number | null;
}

export interface NewUser {
    username: string;
    password: string;
    role: string;
    email?: string;
    display_name?: string;
}

export interface UserPatch {
    role?: string;
    is_active?: boolean;
    password?: string;
}

/** An API key. The cleartext value is not here: it exists once only, in the response to its
 *  creation. */
export interface ApiKeySummary {
    id: string;
    name: string;
    /** The first twelve characters, in clear. This is not a secret. */
    prefix: string | null;
    scopes: string[];
    targetKind: string | null;
    targetId: number | null;
    targetLabel: string | null;
    createdAt: string | null;
    lastUsedAt: string | null;
    expiresAt: string | null;
    /** Computed by the server: two notions of "expired" would diverge by a time zone. */
    isExpired: boolean;
}

export interface NewApiKey {
    name: string;
    scopes: string[];
    target_kind?: string;
    target_id?: number;
    expires_in_days?: number;
}

export interface IssuedApiKey {
    key: ApiKeySummary;
    /** The one and only occurrence of the cleartext value. It never reappears. */
    secret: string;
}

/** A team: the grouping that makes restricted visibility administrable. */
export interface TeamSummary {
    id: number;
    name: string;
    description: string | null;
    /** On the list so the screen can say "four people, two repositories" without one request
     *  per team — and so that a team owning nothing, which grants nothing, is visible at a
     *  glance rather than by opening it. */
    memberCount: number;
    targetCount: number;
    /** Whether the team has its own notification channel — **not the URL**. A webhook URL is a
     *  bearer capability: whoever reads it can post where the team awaits Vectispire's alerts, so no
     *  route returns it and this screen cannot display it back. */
    notified: boolean;
}

export interface TeamTargetAssignment {
    kind: string;
    id: number;
}

export interface ApiKeyTargets {
    repositories: { id: number; label: string }[];
    containers: { id: number; label: string }[];
}

/** An audit log entry. */
export interface AuditEntry {
    id: string;
    timestamp: string | null;
    operationType: string | null;
    resourceId: string | null;
    userId: string | null;
    ipAddress: string | null;
    userAgent: string | null;
    description: string | null;
    previousHash: string | null;
    entryHash: string | null;
}

export interface AuditFilters {
    operation_type?: string;
    user_id?: string;
    search?: string;
    limit?: number;
    offset?: number;
}

/** The result of verifying the integrity chain. */
export interface AuditVerification {
    total: number;
    /** Entries predating the chaining: neither a proof nor an alarm. */
    unverifiable: number;
    verified: number;
    /** The chain holds **and** nothing the mirror kept has left the table. */
    intact: boolean;
    broken: string | null;
    /** Whether a copy outside this database is configured at all. `false` is a state to show,
     *  not a detail to hide: "nothing missing" from a mirror that does not exist reads as
     *  reassurance and is not. */
    mirrored: boolean;
    /** Entries the mirror holds and the table does not — the deletion the chain cannot see,
     *  since nothing descends from the last entry written. */
    missingFromTable: number;
    /** Entries the table holds and the mirror does not: written before the mirror existed,
     *  written while it could not be reached, or inserted by somebody who had the database and
     *  not the file. */
    missingFromMirror: number;
}

/** What the dashboard shows. None of these figures is its own: the posture comes from the
 *  same construction as the Security screen and POST /gate. */
export interface DashboardOverview {
    posture: {
        failingCount: number;
        totalCount: number;
        kevCount: number;
        neverScannedCount: number;
        lastScanFailedCount: number;
        /** Open issues past their remediation window. Zero also means "every window disabled",
         *  which the remediation section of the settings screen is where to check. */
        overdueCount: number;
    };
    /** Outside quality, deliberately. */
    backlogBySeverity: Record<string, number>;
    /** Kept apart, and never mixed into the security backlog: it blocks nothing. */
    qualityTotal: number;
    failing: {
        kind: string;
        targetId: number;
        name: string;
        observed: boolean;
        violations: { rule: string; reason: string; identifier?: string | null; severity?: string | null }[];
    }[];
    recentScans: {
        id: number;
        repoId: number | null;
        containerId: number | null;
        /** Resolved by the server: the ids alone named nothing an operator recognises. */
        targetKind: 'repository' | 'container';
        targetName: string | null;
        status: string;
        findingsCount: number | null;
        error: string | null;
        createdAt: string | null;
    }[];
}

/** One day of the backlog. `open` is the standing total that evening; `opened` and `resolved`
 *  are what moved that day. */
export interface TrendPoint {
    /** An ISO date in UTC, as the server formats it — the axis has to mean the same thing in
     *  two timezones. */
    day: string;
    open: number;
    opened: number;
    resolved: number;
}

/** The backlog over time. Snake case on two fields because the server names them that way. */
export interface Trends {
    points: TrendPoint[];
    /**
     * `null` when nothing was resolved in the window, and **not** zero: zero reads as
     * "everything is fixed the day it appears", the opposite of "there is nothing to measure".
     */
    mean_days_to_resolve: number | null;
    /** The population behind the mean. An average with no denominator is a number people quote
     *  and should not. */
    resolved_in_window: number;
}

/** Un agent, tel que l'administration le voit. */
export interface AgentSummary {
    id: string;
    name: string;
    description: string | null;
    kind: string;
    enabled: boolean;
    credentialsMode: string;
    /** What this agent can reach, comma-separated. `null`: no labelled target. */
    labels: string | null;
    /** Did it announce an ephemeral public key? If not, its secrets travel in clear. */
    sealsCredentials: boolean;
    maxConcurrent: number | null;
    hostname: string | null;
    platform: string | null;
    version: string | null;
    contractVersion: string | null;
    lastSeenAt: string | null;
    /** Seen recently — not "enabled". An enabled but silent agent is the case that matters. */
    online: boolean;
    runningScans: number;
}

export interface RunningScanItem {
    scanId: number;
    targetType: 'repository' | 'container';
    targetId: number;
    targetName: string;
    branch: string;
    agentId: string | null;
    agentName: string;
    claimedAt: string;
    durationSeconds: number;
    requiredLabel: string | null;
}

export interface PendingScanItem {
    scanId: number;
    targetType: 'repository' | 'container';
    targetId: number;
    targetName: string;
    branch: string;
    requiredLabel: string | null;
    queuedAt: string;
    waitDurationSeconds: number;
    isRoutable: boolean;
    positionInQueue: number;
}

export interface QueueStats {
    totalAgents: number;
    onlineAgents: number;
    busyAgents: number;
    idleAgents: number;
    runningScansCount: number;
    pendingScansCount: number;
    scansCompleted24h: number;
    avgScanDurationSeconds: number;
}

export interface AgentActivitySummary {
    runningScans: RunningScanItem[];
    pendingScans: PendingScanItem[];
    stats: QueueStats;
}

export interface NewAgent {
    name: string;
    description?: string;
    credentials_mode: string;
    /** Comma-separated. What this agent can reach. */
    labels?: string;
    max_concurrent?: number;
}

/** A label demanded by targets that no enabled agent carries. */
export interface UnroutableLabel {
    label: string;
    queued: number;
}

export interface IssuedAgent {
    id: string;
    name: string;
    /** The one and only occurrence of the key in clear. */
    secret: string;
}

/** Un agent, tel que l'administration le montre. */


export interface ScanSummary {
    id: number;
    status: string;
    branch: string;
    createdAt: string | null;
    durationMs: number | null;
    findingsCount: number;
    newIssuesCount: number;
    resolvedIssuesCount: number;
    error: string | null;
    claimedBy: string | null;
    attempts: number;
    targetKind: string;
    targetId: number | null;
    targetName: string;
}

export interface ScanFinding {
    id: number;
    type: string;
    severity: string | null;
    identifier: string | null;
    packageName: string | null;
    packageVersion: string | null;
    fixVersions: string | null;
    filePath: string | null;
    line: number | null;
    description: string | null;
    link: string | null;
}

export interface ScanDetail extends ScanSummary {
    subPath: string | null;
    /** What the scanned tree says about itself — `maven`, `gradle`, `npm`, `python`. */
    projectType: string | null;
    /**
     * The project's own version, read from its manifest. Null is a real answer: a repository may
     * carry no manifest, or one that names its ecosystem without stating a version.
     */
    projectVersion: string | null;
    hasSbom: boolean;
    findings: ScanFinding[];
    findingsTotal: number;
    /** Is the list truncated? Saying so avoids believing the scan lighter than it was. */
    findingsTruncated: boolean;
}

/**
 * A setting, as the server describes it.
 *
 * The type and the explanation come from the server rather than being written here: adding a
 * setting must require no change to the interface, and above all the screen must not be able
 * to offer a key that no service reads.
 */
export interface SettingDefinition {
    key: string;
    type: 'boolean' | 'integer' | 'text' | 'severity';
    section: string;
    label: string;
    help: string;
    default: string;
    value: string;
    /** Has it been set, or is this only the default? The two are not said the same way. */
    configured: boolean;
}

/** A stored Semgrep rule set, as the listing returns it — without its files. */
export interface RuleSetSummary {
    id: number;
    name: string;
    contentHash: string;
    ruleCount: number;
    fileCount: number;
    sizeBytes: string;
    isActive: boolean | null;
    uploadedBy: string | null;
    uploadedAt: string;
    activationNote: string | null;
}

/**
 * What activating a rule set would cost.
 *
 * `losingIssues` names the rules that currently have open issues and are absent from the
 * candidate: activating resolves those issues on the next scan, with their triage
 * decisions. This is what the screen must show before offering the button.
 */
export interface RuleSetImpact {
    losingIssues: string[];
    affectedIssues: number;
    addedRules: number;
    removedRules: number;
}

/** What the upstream rule catalogue offers at one pinned tag. */
export interface CataloguePreview {
    upstream: string;
    /** The commit that was actually fetched. The upstream publishes no tags at all. */
    commit: string;
    licenceName: string;
    /** The full text at this tag, never a summary: a summary of a licence is an opinion. */
    licence: string;
    licence_sha256: string;
    /** Language to rule count, so a choice is made on a number rather than on a name. */
    languages: Record<string, number>;
}

/**
 * The detection-and-triage trail.
 *
 * Three facts that live apart in the schema, joined by the server: a scan carries the version of
 * the tree it read, a finding links that scan to an issue, and a decision carries what was
 * concluded about that issue. The joining is the feature.
 */
export interface HistoryRepository {
    id: number;
    name: string;
    url: string;
    branch: string;
    /** The last version actually read. Null means nobody read one, not that there is none. */
    version: string | null;
    projectType: string | null;
    scanCount: number;
    lastScanAt: string | null;
    openIssues: number;
    decisions: number;
}

export interface HistoryDecision {
    fromStatus: string;
    toStatus: string;
    justification: string | null;
    comment: string | null;
    /** Null when nobody decided: the deadline passed. See `origin`. */
    actor: string | null;
    /** `manual` or `expiry`. */
    origin: string;
    occurredAt: string;
    expiresAt: string | null;
    scanId: number | null;
    version: string | null;
}

export interface HistoryIssue {
    id: number;
    type: string;
    identifier: string | null;
    severity: string | null;
    packageName: string | null;
    packageVersion: string | null;
    filePath: string | null;
    /** Where the issue stands **today**, not on the day of the scan. */
    state: string;
    triageStatus: string | null;
    firstSeenAt: string | null;
    resolvedAt: string | null;
    decisions: HistoryDecision[];
}

export interface HistoryScan {
    id: number;
    status: string;
    branch: string;
    version: string | null;
    projectType: string | null;
    createdAt: string;
    durationMs: number | null;
    findingsCount: number;
    newIssuesCount: number;
    resolvedIssuesCount: number;
    error: string | null;
    issues: HistoryIssue[];
}

export interface HistoryDossier {
    repository: HistoryRepository;
    scans: HistoryScan[];
    generatedAt: string;
}

/**
 * One place a component was catalogued.
 *
 * The two versions are named apart on purpose: `componentVersion` is the library's,
 * `projectVersion` is ours — the release it went out in, which is what makes the answer
 * actionable rather than merely true.
 */
export interface InventoryOccurrence {
    component: string;
    componentVersion: string | null;
    purl: string | null;
    type: string | null;
    /** `null` when the SBOM carried no dependency graph: unknown, not transitive. */
    direct: boolean | null;
    targetKind: string;
    targetId: number | null;
    targetName: string;
    branch: string;
    projectVersion: string | null;
    scanId: number;
    scannedAt: string;
}

export interface InventoryResults {
    occurrences: InventoryOccurrence[];
    total: number;
    /** Said explicitly: a capped list read as complete is a wrong answer. */
    truncated: boolean;
}

/**
 * A model-written OWASP posture report.
 *
 * A failed run is a report too: `status: 'failed'` with an `error`, so "the model could not be
 * reached at 09:00" reaches the screen instead of an empty page.
 */
/**
 * One block of the report, parsed by the server.
 *
 * The client places `text` into an element it chose. Nothing here is markup and nothing is
 * interpreted — which is the point: this prose is model output derived from findings written by
 * the audited repository, and handing that to `innerHTML` would be an injection path.
 */
export interface OwaspBlock {
    kind: 'HEADING' | 'CATEGORY' | 'PARAGRAPH' | 'BULLET' | 'NUMBERED' | 'BLOCKQUOTE' | 'TABLE';
    level: number;
    marker: string | null;
    text: string;
    headers?: string[] | null;
    rows?: string[][] | null;
}

export interface OwaspReport {
    id: number;
    status: 'completed' | 'failed';
    /** The model that wrote it: comparing two reports without knowing this is a trap. */
    model: string;
    /** The model's answer as it came. Kept so nothing renders a report the raw text contradicts. */
    content: string | null;
    blocks: OwaspBlock[];
    error: string | null;
    /** The scan it was built from — what dates it and names the version it describes. */
    scanId: number;
    createdAt: string;
}

/** What the configured Ollama answered when asked what it holds. */
export interface OllamaCheck {
    reachable: boolean;
    /** Separate from `reachable`: a reachable host without the model is the usual misconfiguration. */
    modelInstalled: boolean;
    model: string;
    url: string;
    models: string[];
    detail: string;
}

/** Where an issue was seen: one scan, and the project version that scan read. */
export interface IssueSighting {
    scanId: number;
    status: string;
    branch: string;
    version: string | null;
    scannedAt: string;
    severity: string | null;
}

/**
 * One issue with what a backlog row cannot carry.
 *
 * Extends `Issue` because the server unwraps the entity into the same shape the list sends — a
 * second definition would drift from the first the day a column is added.
 */
export interface IssueDetail extends Issue {
    sightings: IssueSighting[];
    decisions: HistoryDecision[];
    isDirectDependency: boolean | null;
}

/** Which ways in this deployment accepts. Read before anybody is authenticated. */
export interface SignInMethods {
    /** False when no issuer is configured: the button is then absent, not disabled. */
    configured: boolean;
    label: string | null;
    /** False when this deployment delegates authentication entirely to the provider — so the
     *  second factor is the realm's, and Vectispire never sees a password. The form is then hidden
     *  rather than shown and refused: an input that cannot work is worse than no input.
     *
     *  Always true when no provider is configured, whatever was asked for: the server refuses to
     *  close the only door that works. */
    password: boolean;
}

/**
 * A stored gate policy, in the vocabulary the gate itself uses.
 *
 * **snake_case, unlike everything else on this file, and deliberately.** These field names are
 * the ones a pipeline already sends to `POST /api/v1/gate` to tighten a verdict for one build;
 * the screen that stores a policy and the build that overrides it are naming the same rules,
 * and two spellings for one vocabulary is how a documented example stops working.
 *
 * `fail_on_severity` is `null` when the severity rule is switched off — which is not the same
 * as absent, and not the same as a threshold of "unknown": it is the policy that blocks on
 * actively exploited findings alone.
 */
export interface GatePolicy {
    kind: 'global' | 'repository' | 'container' | 'built_in';
    target_id: number | null;
    target_name: string | null;
    version: number;
    fail_on_severity: string | null;
    fail_on_kev: boolean;
    fixable_only: boolean;
    include_triaged: boolean;
    include_ai_review: boolean;
    note: string | null;
    created_by: string | null;
    created_at: string | null;
}

export interface GatePolicies {
    policies: GatePolicy[];
    /** What applies where nothing is stored — shown so an operator sees what they depart from. */
    built_in: GatePolicy;
}

/** Every field is sent: the route replaces a policy whole and defaults nothing. */
export interface GatePolicyRequest {
    fail_on_severity: string;
    fail_on_kev: boolean;
    fixable_only: boolean;
    include_triaged: boolean;
    include_ai_review: boolean;
    note: string | null;
}

export interface ComplianceControlAssessment {
    control: {
        id: string;
        name: string;
        requirement: string;
        category: string;
    };
    status: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT';
    scorePercentage: number;
    details: string;
    remediationGuidance: string;
}

export interface ComplianceEvaluation {
    framework: 'NIS_2' | 'DORA' | 'ISO_27001' | 'PCI_DSS' | 'EU_CRA';
    scorePercentage: number;
    overallStatus: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT';
    controls: ComplianceControlAssessment[];
}

export interface TargetCompliance {
    targetId: string;
    name: string;
    type: 'REPOSITORY' | 'CONTAINER';
    gateStatus: 'PASSED' | 'FAILED' | 'NEVER_SCANNED' | 'LAST_SCAN_FAILED' | 'SCANNING' | 'IN_PROGRESS';
    openIssuesCount: number;
    overdueCount: number;
    overallScore: number;
    overallStatus: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT';
    frameworkScores: Record<string, number>;
}

export interface ComplianceSummary {
    evaluations: ComplianceEvaluation[];
    mttr: {
        mttrBySeverityDays: Record<string, number>;
        overallMttrDays: number | null;
        resolvedCount: number;
    };
    overdueCount: number;
    dueSoonCount: number;
    totalMonitoredTargets: number;
    passingGateTargets: number;
    targets?: TargetCompliance[];
}

export interface GraphNode {
    id: string;
    label: string;
    type: 'TARGET' | 'PACKAGE' | 'CVE';
    version: string | null;
    ecosystem: string | null;
    riskScore: number;
    isDirect: boolean;
    cves: string[];
}

export interface GraphEdge {
    source: string;
    target: string;
    relationship: string;
}

export interface DependencyGraph {
    nodes: GraphNode[];
    edges: GraphEdge[];
}

export interface TargetImpact {
    targetId: number;
    targetKind: 'REPOSITORY' | 'CONTAINER';
    targetName: string;
    targetContext: string;
    sourceFile: string;
    purl: string | null;
    packageName: string;
    packageVersion: string;
    isDirect: boolean;
    cves: string[];
    reachability: string;
    scanId: number;
}

export interface TopImpactPackage {
    packageName: string;
    ecosystem: string;
    affectedTargetsCount: number;
    directUsages: number;
    transitiveUsages: number;
    totalCves: number;
    maxCvss: number;
    blastRadiusScore: number;
}

export interface BlastRadiusReport {
    query: string;
    queryType: 'PACKAGE' | 'CVE';
    totalTargetsAffected: number;
    directUsages: number;
    transitiveUsages: number;
    totalAssociatedCves: number;
    blastRadiusScore: number;
    targets: TargetImpact[];
    graph: DependencyGraph;
}

export interface ThreatIntelRecord {
    cveId: string;
    isKev: boolean;
    epssScore: number | null;
    epssPercentile: number | null;
    dateAdded: string | null;
    notes: string | null;
}

export interface EpssPrioritizedIssue {
    issueId: number;
    identifier: string;
    title: string;
    severity: string;
    cvssScore: number | null;
    epssScore: number | null;
    epssPercentile: number | null;
    isKev: boolean;
    reachability: string;
    targetName: string;
    targetKind: string;
    priorityScore: number;
    priorityTier: 'CRITICAL_ARMED' | 'HIGH_PROBABLE' | 'MEDIUM_THEORETICAL' | 'LOW_PROBABILITY';
    recommendedAction: string;
}

export interface EpssFleetSummary {
    totalVulnerabilities: number;
    activeKevCount: number;
    highEpssCount: number;
    reachableEpssCount: number;
    averageFleetEpss: number;
    topPriorities: EpssPrioritizedIssue[];
    breakdownByTier: Record<string, number>;
}

export interface NotificationChannelStatus {
    type: string;
    name: string;
    destination: string;
    configured: boolean;
    supportedEvents: string[];
}

export interface NotificationTestResult {
    type: string;
    success: boolean;
    message: string;
    testedAt: string;
}

export interface AiVulnerabilityAdvice {
    identifier: string;
    title: string;
    summaryExplanation: string;
    exploitMechanics: string;
    exposureAssessment: string;
    remediation: {
        fixAction: string;
        suggestedVersion: string;
        codeSnippetOrDiff: string;
        cliCommand: string;
    };
    vexSuggestion: {
        status: string;
        justification: string;
        impactStatement: string;
        actionStatement: string;
    };
    references: string[];
}

export interface LicenseConflict {
    packageName: string;
    packageVersion: string;
    licenseExpression: string;
    riskCategory: string;
    targetKind: string;
    targetName: string;
    compatibility: 'COMPATIBLE' | 'CONDITIONAL' | 'INCOMPATIBLE_BLOCKING';
    legalRiskExplanation: string;
    remediationAdvice: string;
}

export interface CompatibilityCell {
    targetLicenseType: string;
    dependencyLicenseCategory: string;
    compatibility: string;
    ruleDescription: string;
}

export interface PostureTrendAnalytics {
    windowDays: number;
    overallMttrDays?: number;
    mttrBySeverity: Record<string, number>;
    totalOpenedInWindow: number;
    totalResolvedInWindow: number;
    netResolutionRatePercentage: number;
    dailySeries: Array<{
        date: string;
        openBacklog: number;
        newlyDiscovered: number;
        newlyResolved: number;
        rollingMttrDays?: number;
    }>;
    targetScoreboard: Array<{
        targetId: number;
        targetKind: string;
        targetName: string;
        openCritical: number;
        openHigh: number;
        openMedium: number;
        openLow: number;
        totalResolved: number;
        targetMttrDays?: number;
        securityScore: number;
        maturityGrade: string;
    }>;
}

export interface ApiEndpointView {
    id: number;
    scanId: number;
    repositoryId: number;
    method: string;
    path: string;
    authRequired: boolean;
    authType: string | null;
    visibility: 'PUBLIC' | 'INTERNAL' | 'UNKNOWN';
    filePath: string | null;
    lineNumber: number | null;
    framework: string | null;
    operationId: string | null;
    summary: string | null;
    tags: string | null;
    shadowStatus: 'DOCUMENTED' | 'SHADOW_API' | 'UNDOCUMENTED' | 'HIGH_RISK_EXPOSURE';
    createdAt: string;
}

export interface ApiContractView {
    id: number;
    repositoryId: number;
    scanId: number | null;
    contractPath: string;
    format: string | null;
    title: string | null;
    version: string | null;
    endpointsCount: number;
    createdAt: string;
}

export interface AttackSurfaceSummary {
    totalEndpoints: number;
    publicEndpoints: number;
    internalEndpoints: number;
    unauthenticatedEndpoints: number;
    shadowEndpoints: number;
    sensitiveUnprotectedEndpoints: number;
}

export interface RepositoryApisOverview {
    repositoryId: number;
    endpoints: ApiEndpointView[];
    contracts: ApiContractView[];
    summary: AttackSurfaceSummary;
}

export interface GlobalAttackSurface {
    totalEndpoints: number;
    publicEndpoints: number;
    internalEndpoints: number;
    unauthenticatedEndpoints: number;
    shadowEndpoints: number;
    sensitiveUnprotectedEndpoints: number;
    frameworks: string[];
    highRiskEndpoints: ApiEndpointView[];
    allEndpoints?: ApiEndpointView[];
}

export type ChangeType = 'ADDED' | 'REMOVED' | 'VERSION_CHANGED' | 'LICENSE_CHANGED' | 'UNCHANGED';

export interface ComponentDelta {
    name: string;
    purl: string | null;
    type: string | null;
    isDirect: boolean | null;
    oldVersion: string | null;
    newVersion: string | null;
    oldLicense: string | null;
    newLicense: string | null;
    changeType: ChangeType;
}

export interface CveDelta {
    cveId: string;
    severity: string | null;
    packageName: string | null;
    version: string | null;
    status: 'INTRODUCED' | 'RESOLVED' | 'PERSISTENT';
}

export interface SbomDiffReport {
    fromScanId: number;
    toScanId: number;
    fromVersion: string;
    toVersion: string;
    addedCount: number;
    removedCount: number;
    versionChangedCount: number;
    licenseChangedCount: number;
    introducedCveCount: number;
    resolvedCveCount: number;
    componentDeltas: ComponentDelta[];
    cveDeltas: CveDelta[];
}

export interface HighImpactFix {
    packageName: string;
    currentVersion: string;
    recommendedVersion: string;
    cveCountResolved: number;
    criticalCveCount: number;
    highCveCount: number;
    estimatedHours: number;
    leverageScore: number;
    affectedCves: string[];
    affectedTargetNames: string[];
}

export interface SecurityDebtReport {
    totalOpenIssues: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    totalEstimatedHours: number;
    totalEstimatedPersonDays: number;
    vulnerabilitiesDebtHours: number;
    secretsDebtHours: number;
    sastDebtHours: number;
    iacDebtHours: number;
    topHighImpactFixes: HighImpactFix[];
}
