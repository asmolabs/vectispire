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
}

export interface LoginResponse {
    token: string;
    expiresAt: string;
    user: AuthenticatedUser;
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
}

export interface NewRepository {
    url: string;
    branch: string;
    name?: string;
    /**
     * A directory inside the repository, when only part of it is a project.
     *
     * camelCase on the wire while its neighbours are snake_case — see `ClientContractTest`.
     * The same repository can be registered more than once with different sub-paths: nothing
     * makes the URL unique, deliberately, because a monorepo holds several projects.
     */
    subPath?: string;
    /** The label an agent must carry to scan this target. Empty: any agent will do. */
    required_agent_label?: string;
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
    lastScan: LastScan | null;
    openIssues: number;
}

export interface NewContainer {
    registry?: string;
    image_name: string;
    tag: string;
    /** The label an agent must carry to scan this target. Empty: any agent will do. */
    required_agent_label?: string;
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
    intact: boolean;
    broken: string | null;
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
    kind: 'HEADING' | 'CATEGORY' | 'PARAGRAPH' | 'BULLET' | 'NUMBERED';
    level: number;
    marker: string | null;
    text: string;
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
}
