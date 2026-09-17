/**
 * The shapes the API returns.
 *
 * **Every response shape here now names a schema the control plane publishes.** This file used to
 * redeclare them by hand, which is how a screen came to read `detail.id` on a response that nests
 * its summary under `scan`, how three server shapes ended up under one name called `Issue`, and how
 * a client kept modelling OpenVEX products as bare strings for months after the server stopped
 * sending them that way. `Schema<'…'>` names a shape; `Refine<>` writes down what the document
 * cannot say about it, checked against it.
 *
 * **Five interfaces remain hand-written, and they are meant to.** `Page<T>` is a client generic.
 * `IssueFilters` and `AuditFilters` are query parameters, which a response schema never describes.
 * `NewRepository` and `NewContainer` are form bodies the document does not publish. None of them
 * has a schema to be adossé to, and inventing one would be the same mistake in the other direction.
 *
 * **What the document still does not say.** It marks a property required only when it is a
 * primitive — a converter in the control plane does that much, because a Java `boolean` has no
 * absent value and no null one, so it is provable rather than intended. It stops short of reference
 * types: a `String` always sent in practice is a promise about the code, and nothing tells it apart
 * from one genuinely null sometimes. Nor does it mark anything nullable, while this server does
 * send `displayName: null`.
 *
 * `Refine<>` is where each such claim is written down, one field at a time and visibly. A claim
 * must name a key the schema has, and a scalar claim must respect the type it declares — so a
 * property renamed upstream fails here rather than being shadowed by the claim about it.
 *
 * `openapi.json` beside this workspace is regenerated and *verified* by `ClientContractSpecTest`
 * in the control plane: a route whose shape changes fails that test rather than this screen. And
 * `asSchema` in `core/testing` reads the test fixtures against the same document, because a type
 * check never looks at a literal.
 */

import type { components } from './api.generated';

/** A shape the control plane declares, named as `openapi.json` names it. */
export type Schema<K extends keyof components['schemas']> = components['schemas'][K];

/**
 * A schema, with the claims the document cannot make written out beside it.
 *
 * Each claim says a property is always sent, or may be `null`, or holds a narrower set of values
 * than `string`. **They are checked against the schema, not layered over it**: a key must be one
 * the schema has, so a property renamed in the control plane fails here rather than being silently
 * shadowed by the claim about it. A scalar claim is checked against the schema's own type too, so
 * an `id` that turns from a number into a string fails the same way.
 *
 * The type check stops at object and array properties, and that is a deliberate hole: a claim
 * there is usually another refined type — {@link UserList} holds {@link UserSummary}\[] — and a
 * refinement is by construction not assignable to the shape it refines, since it adds `null` where
 * the document had nothing. Checking the key is what remains, and it is the check that catches the
 * rename.
 *
 * Primitives need no claim — the document marks those itself. Keep the rest few, and delete each
 * one as its record starts saying so.
 */
export type Claimable<S, K extends keyof S> = NonNullable<S[K]> extends object ? unknown : S[K] | null;

export type Refine<S, Claims extends { [K in keyof Claims]: K extends keyof S ? Claimable<S, K> : never }> =
    Omit<S, keyof Claims> & Claims;

/** `GET /api/v1/auth/me`, and the `user` of a successful login. */
export type AuthenticatedUser = Refine<
    Schema<'UserSummary'>,
    {
        username: string;
        role: string;
        /**
         * Sent on every response and `null` when unset — this deployment does not configure
         * `NON_NULL` inclusion outside SCIM, so the key is there. Nullability is the one thing
         * the document still says nothing about.
         */
        displayName: string | null;
    }
>;

/**
 * `POST /api/v1/auth/login` — every field is genuinely conditional here: a successful login carries
 * `token` and `user`, an MFA challenge carries `mfa_required` and `mfa_token`, and never both.
 * `user`, when present, is the same claim as {@link AuthenticatedUser} rather than the looser shape
 * the document nests here.
 */
export type LoginResponse = Omit<Schema<'LoginResponse'>, 'user'> & { user?: AuthenticatedUser };

/** `POST /api/v1/auth/mfa/setup` */
export type MfaSetupResponse = Refine<
    Schema<'SetupResponse'>,
    { secret: string; qrCodeUri: string; issuer: string }
>;

/** `POST /api/v1/auth/mfa/enable` */
export type MfaEnableResponse = Refine<Schema<'EnableResponse'>, { backupCodes: string[] }>;

/**
 * `authHeader` is not in the response: it only travels outbound, and the server never sends it
 * back — `hasAuthHeader` says whether one exists, which is all a screen can know of a secret.
 */
export type SiemConfig = Refine<
    Schema<'SiemConfigResponse'>,
    {
        protocol: 'WEBHOOK' | 'SYSLOG_UDP' | 'SYSLOG_TCP' | 'SYSLOG_TLS';
        minSeverity: string;
        endpoint: string | null;
        updatedAt: string | null;
    }
> & { authHeader?: string };

export type SiemTestResult = Refine<Schema<'TestResult'>, { message: string }>;

export type ThreatIntelSyncStatus = Refine<
    Schema<'ThreatIntelSyncStatus'>,
    { status: string; lastSyncedAt: string | null }
>;

/** A product a statement is about, as the standard names it: an object, never a string. */
export type OpenVexProduct = Refine<Schema<'Product'>, { '@id': string }>;

/**
 * A VEX statement.
 *
 * **`products` held bare strings here.** The control plane already settled that disagreement on
 * its side — two OpenVEX models coexisted there, one of which modelled products as strings, so the
 * ingestion route could not read back what the export produced. The client kept the stale half; no
 * screen reads it, which is exactly why nobody had seen it.
 */
export type OpenVexStatement = Refine<
    Schema<'OpenVexStatement'>,
    {
        vulnerability: { name: string };
        products: OpenVexProduct[];
        status: NonNullable<Schema<'OpenVexStatement'>['status']>;
        justification?: NonNullable<Schema<'OpenVexStatement'>['justification']>;
        impact_statement?: string;
        action_statement?: string;
        status_notes?: string;
    }
>;

export type OpenVexDocument = Refine<
    Schema<'OpenVexDocument'>,
    {
        '@context': string;
        '@id': string;
        author: string;
        role: string;
        timestamp: string;
        tooling: string;
        statements: OpenVexStatement[];
    }
>;

/**
 * The document types `riskCategory` as a bare `string` with an enum, which the generator widens to
 * a union anyway — but naming it here keeps the screens reading one name rather than five literals.
 */
export type LicenseRiskCategory =
    | 'PERMISSIVE'
    | 'WEAK_COPYLEFT'
    | 'STRONG_COPYLEFT'
    | 'FORBIDDEN'
    | 'UNKNOWN';

export type LicenseEntry = Refine<
    Schema<'LicenseEntry'>,
    {
        packageName: string;
        packageVersion: string;
        license: string;
        riskCategory: LicenseRiskCategory;
        targetKind: string;
        targetName: string;
        purl: string | null;
        violationReason: string | null;
        targetId: number | null;
    }
>;

export type LicensePolicy = Refine<
    Schema<'LicensePolicy'>,
    {
        disallowedCategories: LicenseRiskCategory[];
        explicitlyAllowedLicenses: string[];
        explicitlyDisallowedLicenses: string[];
    }
>;

/**
 * `breakdownByRisk` carries only the categories present in the estate — `Partial`, therefore, not
 * a complete `Record`. Declaring it complete made the compiler call the template's `?? 0` guards
 * redundant, when they are exactly what stops a sum rendering `NaN` on a compliance figure the day
 * a category is absent.
 */
export type LicenseSummary = Refine<
    Schema<'LicenseSummary'>,
    { breakdownByRisk: Partial<Record<LicenseRiskCategory, number>> }
>;

export type SecurityGrade = 'A_PLUS' | 'A' | 'B' | 'C' | 'D' | 'F';

export type SecurityScorecard = Refine<
    Schema<'SecurityScorecard'>,
    {
        targetKind: string;
        targetName: string;
        grade: SecurityGrade;
        recommendations: string[];
        targetId: number | null;
    }
>;

export type BadgeState = Refine<
    Schema<'BadgeState'>,
    { token: string | null; url: string | null }
>;

export type PinnedSigningKey = Refine<
    Schema<'PinnedSigningKey'>,
    { id: string; privateKey: string | null }
>;

/** Ce qui a produit le résultat, et sur quoi il porte. */
export type AttestationBuilder = Refine<Schema<'Builder'>, { id: string; version: string }>;

export type AttestationSubject = Refine<
    Schema<'Subject'>,
    { name: string; digest: Record<string, string> }
>;

export type AttestationInvocation = Refine<
    Schema<'Invocation'>,
    {
        scanId: number;
        targetKind: string;
        targetName: string;
        branch: string;
        timestamp: string;
        commitSha: string | null;
    }
>;

export type AttestationPolicy = Refine<
    Schema<'PolicyAssessment'>,
    { violations: string[]; enforcedPolicy: string }
>;

/** Les sept compteurs sont primitifs : le document les marque tous « toujours envoyés ». */
export type AttestationFindings = Schema<'FindingsSummary'>;

export type AttestationPredicate = Refine<
    Schema<'Predicate'>,
    {
        builder: AttestationBuilder;
        invocation: AttestationInvocation;
        policy: AttestationPolicy;
        findings: AttestationFindings;
        sbomDigestSha256: string | null;
    }
>;

export type InTotoAttestation = Refine<
    Schema<'InTotoAttestation'>,
    {
        _type: string;
        predicateType: string;
        subject: AttestationSubject[];
        predicate: AttestationPredicate;
    }
>;

/**
 * A row of the backlog.
 *
 * <b>Three server shapes used to live under this one name.</b> The list sends `BacklogEntry`, which
 * carries the remediation window and the resolved target; a triage or a ticket attachment answers
 * with `IssueEntity`, which carries neither; the detail route sends `IssueDetail`. Declaring one
 * interface for all three made the compiler promise `slaState` on a triage response that has never
 * contained it — no screen happened to read it there, so nothing broke and nothing said anything.
 * They are three types below, named after what the server actually sends.
 */
export type Issue = Refine<
    Schema<'BacklogEntry'>,
    {
        id: number;
        /** Resolved by the server, so one target is never named two things on two screens. */
        targetKind: 'repository' | 'container';
        type: string;
        state: string;
        firstSeenAt: string;
        lastSeenAt: string;
        triageStatus: string;
        repoId: number | null;
        containerId: number | null;
        targetName: string | null;
        identifier: string | null;
        severity: string | null;
        packageName: string | null;
        packageVersion: string | null;
        purl: string | null;
        filePath: string | null;
        line: number | null;
        cvssScore: number | null;
        epssScore: number | null;
        fixState: string | null;
        fixVersions: string | null;
        link: string | null;
        description: string | null;
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
        /** When this issue's remediation window closes; null when none applies — a severity with
         *  no window, or an issue already settled or closed.
         *
         *  **Computed by the server**, like the gate verdict. Deriving it here from the policy
         *  would be a second implementation of the deadline, and the two would disagree the day it
         *  moves. */
        slaDueAt: string | null;
        /** `on_time`, `due_soon` or `overdue`; null with no deadline. A state and not a date to
         *  compare, so "late" means the same thing on this screen, in an export and in a report. */
        slaState: 'on_time' | 'due_soon' | 'overdue' | null;
        /** Days until due, **negative when late**. One signed field: "3 days late" and "due in 12
         *  days" are one measurement read from opposite sides. */
        slaDays: number | null;
    }
>;

/**
 * What a triage or a ticket attachment answers with: the stored issue, without the remediation
 * window the backlog query computes and without the target's resolved name. Call sites use it to
 * read back what the server accepted — a trimmed ticket reference, a refused one — and then
 * reload.
 */
export type TriagedIssue = Refine<
    Schema<'IssueEntity'>,
    {
        id: number;
        type: string;
        state: string;
        triageStatus: string;
        identifier: string | null;
        severity: string | null;
        ticketRef: string | null;
        ticketUrl: string | null;
    }
>;

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

/**
 * The three optional fields are sent as `null` rather than omitted, which the record accepts —
 * `String` and `Integer`, both nullable. The document has no way to say "may be null on the way
 * in", so the claim is made here.
 */
export type TriageRequest = Refine<
    Schema<'TriageRequest'>,
    {
        status: string;
        justification?: string | null;
        comment?: string | null;
        expires_in_days?: number | null;
    }
>;

export type BulkTriageRequest = Refine<
    Schema<'BulkTriageRequest'>,
    {
        status: string;
        justification?: string | null;
        comment?: string | null;
        expires_in_days?: number | null;
        /** At most 500 — the server refuses a longer batch rather than truncating it. */
        ids: number[];
    }
>;

export type GateViolation = Refine<
    Schema<'ViolationView'>,
    {
        /** `coverage` fails on the absence of an examination rather than on a finding. */
        rule: 'kev' | 'severity' | 'coverage';
        /** Null on a `coverage` violation: there is no issue behind it, which is the point. */
        issueId: number | null;
        severity: string | null;
        reason: string;
        identifier: string | null;
        package: string | null;
        fixVersions: string | null;
    }
>;

export type ResolvedGatePolicy = Refine<
    Schema<'AppliedPolicy'>,
    {
        source: 'target' | 'global' | 'built-in';
        description: string;
        failOnSeverity: string | null;
        version: number | null;
    }
>;

export type Observation = 'ok' | 'never_scanned' | 'last_scan_failed' | 'in_progress';

/** What the gate concluded about one target, and on how much. */
export type GateVerdict = Refine<
    Schema<'VerdictView'>,
    { violations: GateViolation[]; countsBySeverity: Record<string, number> }
>;

/** Which policy decided, and which revision of it. */
export type OverviewPolicy = Refine<
    Schema<'OverviewPolicyView'>,
    { source: string; version: number | null }
>;

export type TargetPosture = Refine<
    Schema<'TargetView'>,
    {
        kind: 'repository' | 'container';
        name: string;
        observation: Observation;
        verdict: GateVerdict;
        policy: OverviewPolicy;
        lastScanAt: string | null;
        lastScanId: number | null;
    }
>;

export type SecurityOverview = Refine<Schema<'SecurityOverviewView'>, { targets: TargetPosture[] }>;

/** A grouped count — a rule, a file or a repository, and how many findings it carries. */
export type Tally = Refine<Schema<'Bucket'>, { label: string | null }>;

export type QualityOverview = Refine<
    Schema<'QualityOverview'>,
    { topRules: Tally[]; topFiles: Tally[]; topTargets: Tally[] }
>;

export type AssetTier = 'TIER_1_MISSION_CRITICAL' | 'TIER_2_BUSINESS_OPERATIONAL' | 'TIER_3_INTERNAL';

/** A monitored repository, with the state of its last scan. */
export type MonitoredRepository = Refine<
    Schema<'RepositorySummary'>,
    {
        id: number;
        url: string;
        branch: string;
        /** Computed by the server, so the same repository carries the same name everywhere. */
        displayName: string;
        name: string | null;
        subPath: string | null;
        scanIntervalMinutes: number | null;
        scanCron: string | null;
        /** The label an agent must carry to scan this target. Sent by the server all along. */
        requiredAgentLabel: string | null;
        sshKeyId: string | null;
        lastScan: LastScan | null;
        tier?: AssetTier;
    }
>;

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
export type LastScan = Refine<
    Schema<'LastScan'>,
    { id: number; status: string; createdAt: string | null; error: string | null }
>;

/** A monitored container image. */
export type MonitoredContainer = Refine<
    Schema<'ContainerSummary'>,
    {
        id: number;
        imageName: string;
        tag: string;
        /** Computed by the server: the form a registry expects. */
        reference: string;
        registry: string | null;
        scanIntervalMinutes: number | null;
        scanCron: string | null;
        requiredAgentLabel: string | null;
        lastScan: LastScan | null;
        tier?: AssetTier;
    }
>;

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
/**
 * How readable the stored private half is. The document types it `string`: the server computes it
 * rather than persisting an enum, so nothing in the schema narrows it and the screen would happily
 * compare it against a value that can never occur.
 */
export type EncryptionState = 'current' | 'previous_key' | 'unreadable';

/** A deployment key. The private half never appears here: the server does not return it, and
 *  no screen would have a reason to show it. */
export type SshKeySummary = Refine<
    Schema<'SshKeySummary'>,
    {
        id: string;
        name: string;
        createdAt: string;
        encryptionState: EncryptionState;
        publicKey: string | null;
    }
>;

export type NewSshKey = Refine<Schema<'SshKeyCreateRequest'>, { name: string; private_key: string }>;

/** An account. The password hash never appears here: the server does not return it, and a
 *  bcrypt hash that leaves the server is a hash to be cracked. */
export type UserSummary = Refine<
    Schema<'UserAdminSummary'>,
    {
        id: number;
        username: string;
        role: string;
        createdAt: string;
        email: string | null;
        displayName: string | null;
    }
>;

export type UserList = Refine<
    Schema<'UserListing'>,
    {
        users: UserSummary[];
        /** So the screen does not offer actions the server will refuse anyway. */
        currentUserId: number | null;
    }
>;

export type NewUser = Refine<
    Schema<'UserCreateRequest'>,
    { username: string; password: string; role: string }
>;

/** Every field is a field left alone when absent, so the schema already says it exactly. */
export type UserPatch = Schema<'UserUpdateRequest'>;

/** An API key. The cleartext value is not here: it exists once only, in the response to its
 *  creation. */
export type ApiKeySummary = Refine<
    Schema<'ApiKeySummary'>,
    {
        id: string;
        name: string;
        scopes: string[];
        /** The first twelve characters, in clear. This is not a secret. */
        prefix: string | null;
        targetKind: string | null;
        targetId: number | null;
        targetLabel: string | null;
        createdAt: string | null;
        lastUsedAt: string | null;
        expiresAt: string | null;
    }
>;

export type NewApiKey = Refine<Schema<'ApiKeyCreateRequest'>, { name: string; scopes: string[] }>;

export type IssuedApiKey = Refine<
    Schema<'IssuedKey'>,
    {
        key: ApiKeySummary;
        /** The one and only occurrence of the cleartext value. It never reappears. */
        secret: string;
    }
>;

/** A team: the grouping that makes restricted visibility administrable.
 *
 *  `memberCount` and `targetCount` are on the list so the screen can say "four people, two
 *  repositories" without one request per team — and so that a team owning nothing, which grants
 *  nothing, is visible at a glance rather than by opening it.
 *
 *  `notified` says whether the team has its own notification channel — **not the URL**. A webhook
 *  URL is a bearer capability: whoever reads it can post where the team awaits Vectispire's alerts,
 *  so no route returns it and this screen cannot display it back. */
export type TeamSummary = Refine<
    Schema<'TeamSummary'>,
    { id: number; name: string; description: string | null }
>;

export type TeamTargetAssignment = Refine<Schema<'TeamTargetAssignment'>, { kind: string; id: number }>;

/**
 * A target an account sees directly, without going through a team.
 *
 * The same shape as {@link TeamTargetAssignment} and still distinct — the control plane names them
 * separately too. The two sets add up server-side, and merging them into one type is how a screen
 * comes to replace one believing it replaces the other.
 */
export type UserTargetAssignment = Refine<Schema<'UserTargetAssignment'>, { kind: string; id: number }>;

/** A target a key may be scoped to, as the picker needs it: identified and named. */
export type TargetOption = Refine<Schema<'TargetOption'>, { id: number; label: string }>;

export type ApiKeyTargets = Refine<
    Schema<'Targets'>,
    { repositories: TargetOption[]; containers: TargetOption[] }
>;

/** An audit log entry. Everything but its identity can be absent, and is sent as `null`. */
export type AuditEntry = Refine<
    Schema<'AuditLogEntity'>,
    {
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
>;

export interface AuditFilters {
    operation_type?: string;
    user_id?: string;
    search?: string;
    limit?: number;
    offset?: number;
}

/** The result of verifying the integrity chain. */
/**
 * The state of the audit chain, as the server alone can compute it.
 *
 * `unverifiable` counts entries predating the chaining: neither a proof nor an alarm. `intact`
 * means the chain holds **and** nothing the mirror kept has left the table. `mirrored` says
 * whether a copy outside this database is configured at all — `false` is a state to show, not a
 * detail to hide: "nothing missing" from a mirror that does not exist reads as reassurance and is
 * not. `missingFromTable` counts entries the mirror holds and the table does not — the deletion
 * the chain cannot see, since nothing descends from the last entry written. `missingFromMirror`
 * counts the reverse: written before the mirror existed, written while it could not be reached, or
 * inserted by somebody who had the database and not the file.
 */
export type AuditVerification = Refine<Schema<'Verification'>, { broken: string | null }>;

/** What the dashboard shows. None of these figures is its own: the posture comes from the
 *  same construction as the Security screen and POST /gate. */
/**
 * The fleet's counters. `overdueCount` is open issues past their remediation window; zero also
 * means "every window disabled", which the remediation section of the settings screen is where to
 * check.
 */
export type PostureCounts = Schema<'Posture'>;

export type FailingTarget = Refine<
    Schema<'FailingTarget'>,
    {
        kind: string;
        targetId: number;
        name: string;
        /** The same {@link GateViolation} every other route sends. It used to be the domain record
         *  here, whose `rule` arrives as `KEV` where the screen compares `'kev'`. */
        violations: GateViolation[];
    }
>;

export type RecentScan = Refine<
    Schema<'RecentScan'>,
    {
        id: number;
        status: string;
        /** Resolved by the server: the ids alone named nothing an operator recognises. */
        targetKind: 'repository' | 'container';
        targetName: string | null;
        repoId: number | null;
        containerId: number | null;
        error: string | null;
        createdAt: string | null;
    }
>;

export type DashboardOverview = Refine<
    Schema<'DashboardOverview'>,
    {
        posture: PostureCounts;
        /** Outside quality, deliberately. */
        backlogBySeverity: Record<string, number>;
        failing: FailingTarget[];
        recentScans: RecentScan[];
    }
>;

export type TrendPoint = Refine<
    Schema<'TrendPoint'>,
    {
        /** An ISO date in UTC, as the server formats it — the axis has to mean the same thing in
         *  two timezones. */
        day: string;
    }
>;

export type Trends = Refine<
    Schema<'Trends'>,
    {
        points: TrendPoint[];
        /**
         * `null` when nothing was resolved in the window, and **not** zero: zero reads as
         * "everything is fixed the day it appears", the opposite of "there is nothing to measure".
         * The population behind it, `resolved_in_window`, is always sent — an average with no
         * denominator is a number people quote and should not.
         */
        mean_days_to_resolve: number | null;
    }
>;

/** Un agent, tel que l'administration le voit. */
export type AgentSummary = Refine<
    Schema<'AgentSummary'>,
    {
        id: string;
        name: string;
        kind: string;
        credentialsMode: string;
        description: string | null;
        /** What this agent can reach, comma-separated. `null`: no labelled target. */
        labels: string | null;
        maxConcurrent: number | null;
        hostname: string | null;
        platform: string | null;
        version: string | null;
        contractVersion: string | null;
        lastSeenAt: string | null;
    }
>;

export type RunningScanItem = Refine<
    Schema<'RunningScanItem'>,
    {
        scanId: number;
        targetType: 'repository' | 'container';
        targetId: number;
        targetName: string;
        branch: string;
        agentName: string;
        claimedAt: string;
        agentId: string | null;
        requiredLabel: string | null;
    }
>;

export type PendingScanItem = Refine<
    Schema<'PendingScanItem'>,
    {
        scanId: number;
        targetType: 'repository' | 'container';
        targetId: number;
        targetName: string;
        branch: string;
        queuedAt: string;
        requiredLabel: string | null;
    }
>;

/** Every figure is a count the server computes; the document marks them all as always sent. */
export type QueueStats = Schema<'QueueStats'>;

export type AgentActivitySummary = Refine<
    Schema<'AgentActivitySummary'>,
    { runningScans: RunningScanItem[]; pendingScans: PendingScanItem[]; stats: QueueStats }
>;

export type NewAgent = Refine<
    Schema<'AgentCreateRequest'>,
    { name: string; credentials_mode: string }
>;

export type UnroutableLabel = Refine<Schema<'UnroutableLabel'>, { label: string }>;

export type IssuedAgent = Refine<
    Schema<'DeclaredAgent'>,
    {
        id: string;
        name: string;
        /** The one and only occurrence of the key in clear. */
        secret: string;
    }
>;

export type ScanSummary = Refine<
    Schema<'ScanSummary'>,
    {
        id: number;
        status: string;
        branch: string;
        targetKind: string;
        targetName: string;
        createdAt: string | null;
        durationMs: number | null;
        error: string | null;
        claimedBy: string | null;
        targetId: number | null;
    }
>;

export type ScanFinding = Refine<
    Schema<'FindingView'>,
    {
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
>;

/**
 * One scan, with what the list cannot carry.
 *
 * <b>The summary is nested under `scan`, not spread across this object.</b> It was declared here as
 * `extends ScanSummary`, and the screen read `detail.id`, `detail.branch`, `detail.status` and the
 * three counters straight off the response — where the server has never put them. Ten fields of
 * that page rendered blank, and the type said they could not be. Nothing failed loudly enough for
 * anyone to look.
 */
export type ScanDetail = Refine<
    Schema<'ScanDetail'>,
    {
        scan: ScanSummary;
        findings: ScanFinding[];
        subPath: string | null;
        /** What the scanned tree says about itself — `maven`, `gradle`, `npm`, `python`. */
        projectType: string | null;
        /**
         * The project's own version, read from its manifest. Null is a real answer: a repository
         * may carry no manifest, or one that names its ecosystem without stating a version.
         */
        projectVersion: string | null;
    }
>;

export type SettingDefinition = Refine<
    Schema<'SettingView'>,
    {
        key: string;
        type: 'boolean' | 'integer' | 'text' | 'severity';
        section: string;
        label: string;
        help: string;
        default: string;
        value: string;
    }
>;

/** A stored Semgrep rule set, as the listing returns it — without its files. */
export type RuleSetSummary = Refine<
    Schema<'RuleSetSummary'>,
    {
        id: number;
        name: string;
        contentHash: string;
        sizeBytes: string;
        uploadedAt: string;
        isActive: boolean | null;
        uploadedBy: string | null;
        activationNote: string | null;
    }
>;

export type RuleSetImpact = Refine<Schema<'TriageImpact'>, { losingIssues: string[] }>;

export type CataloguePreview = Refine<
    Schema<'CataloguePreview'>,
    {
        upstream: string;
        /** The commit that was actually fetched. The upstream publishes no tags at all. */
        commit: string;
        licenceName: string;
        /** The full text at this tag, never a summary: a summary of a licence is an opinion. */
        licence: string;
        licence_sha256: string;
        /** Language to rule count, so a choice is made on a number rather than on a name. */
        languages: Record<string, number>;
        /**
         * OWASP category to the number of rules that declare it.
         *
         * **Answers before the import a question that could only be asked after it.** The grid
         * marks a category "not covered" when no installed rule declares it — so a grey square
         * means either a limit of the product or an import nobody made, and nothing told them
         * apart.
         */
        categories: Record<string, number>;
    }
>;

/**
 * The detection-and-triage trail.
 *
 * Three facts that live apart in the schema, joined by the server: a scan carries the version of
 * the tree it read, a finding links that scan to an issue, and a decision carries what was
 * concluded about that issue. The joining is the feature.
 */
export type HistoryRepository = Refine<
    Schema<'Repository'>,
    {
        id: number;
        name: string;
        url: string;
        branch: string;
        /** The last version actually read. Null means nobody read one, not that there is none. */
        version: string | null;
        projectType: string | null;
        lastScanAt: string | null;
    }
>;

export type HistoryDecision = Refine<
    Schema<'Decision'>,
    {
        fromStatus: string;
        toStatus: string;
        occurredAt: string;
        /** `manual` or `expiry`. */
        origin: string;
        justification: string | null;
        comment: string | null;
        /** Null when nobody decided: the deadline passed. See `origin`. */
        actor: string | null;
        expiresAt: string | null;
        scanId: number | null;
        version: string | null;
    }
>;

export type HistoryIssue = Refine<
    Schema<'ObservedIssue'>,
    {
        id: number;
        type: string;
        /** Where the issue stands **today**, not on the day of the scan. */
        state: string;
        identifier: string | null;
        severity: string | null;
        packageName: string | null;
        packageVersion: string | null;
        filePath: string | null;
        triageStatus: string | null;
        firstSeenAt: string | null;
        resolvedAt: string | null;
        decisions: HistoryDecision[];
    }
>;

export type HistoryScan = Refine<
    Schema<'Scan'>,
    {
        id: number;
        status: string;
        branch: string;
        createdAt: string;
        version: string | null;
        projectType: string | null;
        durationMs: number | null;
        error: string | null;
        issues: HistoryIssue[];
    }
>;

export type HistoryDossier = Refine<
    Schema<'Dossier'>,
    { repository: HistoryRepository; scans: HistoryScan[]; generatedAt: string }
>;

/**
 * One place a component was catalogued.
 *
 * The two versions are named apart on purpose: `componentVersion` is the library's,
 * `projectVersion` is ours — the release it went out in, which is what makes the answer
 * actionable rather than merely true.
 */
export type InventoryOccurrence = Refine<
    Schema<'Occurrence'>,
    {
        component: string;
        targetKind: string;
        targetName: string;
        branch: string;
        scanId: number;
        scannedAt: string;
        componentVersion: string | null;
        purl: string | null;
        type: string | null;
        /** `null` when the SBOM carried no dependency graph: unknown, not transitive. */
        direct: boolean | null;
        targetId: number | null;
        projectVersion: string | null;
    }
>;

/** `truncated` is said explicitly: a capped list read as complete is a wrong answer. */
export type InventoryResults = Refine<
    Schema<'Results'>,
    { occurrences: InventoryOccurrence[] }
>;

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
export type OwaspBlock = Refine<
    Schema<'Block'>,
    {
        kind: 'HEADING' | 'CATEGORY' | 'PARAGRAPH' | 'BULLET' | 'NUMBERED' | 'BLOCKQUOTE' | 'TABLE';
        marker: string | null;
        text: string;
        headers?: string[] | null;
        rows?: string[][] | null;
    }
>;

export type OwaspReport = Refine<
    Schema<'Report'>,
    {
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
>;

/** What the configured model endpoint answered when asked what it offers. */
export type OllamaCheck = Refine<
    Schema<'OllamaCheck'>,
    {
        model: string;
        url: string;
        models: string[];
        detail: string;
        /** `ollama` or `openai` — which wire protocol was spoken. */
        provider: string;
    }
>;

/** Where an issue was seen: one scan, and the project version that scan read. */
export type IssueSighting = Refine<
    Schema<'Sighting'>,
    { scanId: number; status: string; branch: string; scannedAt: string; version: string | null }
>;

/**
 * One issue with what a backlog row cannot carry.
 *
 * Its own schema, not an extension of {@link Issue}: the detail route sends the sightings and the
 * decisions, and does not send the remediation window. Extending the row is what quietly promised
 * an `slaState` here.
 */
export type IssueDetail = Refine<
    Schema<'IssueDetail'>,
    {
        id: number;
        targetKind: 'repository' | 'container';
        type: string;
        state: string;
        firstSeenAt: string;
        lastSeenAt: string;
        triageStatus: string;
        repoId: number | null;
        containerId: number | null;
        targetName: string | null;
        identifier: string | null;
        severity: string | null;
        packageName: string | null;
        packageVersion: string | null;
        purl: string | null;
        filePath: string | null;
        line: number | null;
        cvssScore: number | null;
        epssScore: number | null;
        fixState: string | null;
        fixVersions: string | null;
        link: string | null;
        description: string | null;
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
        sightings: IssueSighting[];
        decisions: HistoryDecision[];
    }
>;

/** Which ways in this deployment accepts. Read before anybody is authenticated. */
export type SignInMethods = Refine<
    Schema<'SignInMethods'>,
    {
        label: string | null;
        /** The brand name for this deployment (default: Vectispire). */
        brandName?: string;
        /** The reference GitLab URL for upstream Vectispire project. */
        gitlabUrl?: string;
    }
>;

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
export type GatePolicy = Refine<
    Schema<'GatePolicyView'>,
    {
        kind: 'global' | 'repository' | 'container' | 'built_in';
        target_id: number | null;
        target_name: string | null;
        fail_on_severity: string | null;
        note: string | null;
        created_by: string | null;
        created_at: string | null;
    }
>;

export type GatePolicies = Refine<
    Schema<'PoliciesResponse'>,
    {
        policies: GatePolicy[];
        /** What applies where nothing is stored — shown so an operator sees what they depart from. */
        built_in: GatePolicy;
    }
>;

/**
 * **Every field is sent on every write**, except one. The server refuses a partial policy rather
 * than filling in the missing half, because a stored value would be silently reinstated under a
 * version number claiming somebody chose it.
 *
 * `fail_on_uncovered_languages` is the exception: it did not exist before, so absent means "the
 * behaviour you already had". It is still sent here so the form says what it does, but the type
 * allows it absent as the server does.
 */
export type GatePolicyRequest = Refine<
    Schema<'PolicyRequest'>,
    {
        fail_on_severity: string;
        fail_on_kev: boolean;
        fixable_only: boolean;
        include_triaged: boolean;
        include_ai_review: boolean;
        fail_on_uncovered_languages: boolean;
        note: string | null;
    }
>;

/** The category a control belongs to, as the document enumerates it. */
export type ComplianceCategory = Schema<'ComplianceControl'>['category'];

/** A control's verdict, and the framework's own. One vocabulary for both. */
export type ComplianceStatus = 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT';

/**
 * The frameworks evaluated, **read from the document**.
 *
 * They were listed by hand, and `SOC_2` was missing: an exhaustive `switch` would have omitted it
 * with no word from the compiler, because exhaustiveness is measured against the type and not
 * against reality.
 */
export type ComplianceFramework = NonNullable<Schema<'ComplianceEvaluation'>['framework']>;

export type ComplianceControl = Refine<
    Schema<'ComplianceControl'>,
    { id: string; name: string; requirement: string; category: ComplianceCategory }
>;

export type ComplianceControlAssessment = Refine<
    Schema<'ControlAssessment'>,
    {
        control: ComplianceControl;
        status: ComplianceStatus;
        details: string;
        remediationGuidance: string;
    }
>;

export type ComplianceEvaluation = Refine<
    Schema<'ComplianceEvaluation'>,
    {
        framework: ComplianceFramework;
        overallStatus: ComplianceStatus;
        controls: ComplianceControlAssessment[];
    }
>;

export type TargetCompliance = Refine<
    Schema<'TargetCompliance'>,
    {
        targetId: string;
        name: string;
        type: 'REPOSITORY' | 'CONTAINER';
        gateStatus:
            | 'PASSED'
            | 'FAILED'
            | 'NEVER_SCANNED'
            | 'LAST_SCAN_FAILED'
            | 'SCANNING'
            | 'IN_PROGRESS';
        overallStatus: ComplianceStatus;
        frameworkScores: Record<string, number>;
    }
>;

/**
 * `overallMttrDays` is null when nothing was resolved in the window, and `resolvedCount` is the
 * population behind it — an average with no denominator is a number people quote and should not.
 */
export type ComplianceMttr = Refine<
    Schema<'MttrResult'>,
    { mttrBySeverityDays: Record<string, number>; overallMttrDays: number | null }
>;

export type ComplianceSummary = Refine<
    Schema<'ComplianceSummary'>,
    { evaluations: ComplianceEvaluation[]; mttr: ComplianceMttr; targets?: TargetCompliance[] }
>;

export type GraphNode = Refine<
    Schema<'GraphNode'>,
    {
        id: string;
        label: string;
        type: 'TARGET' | 'PACKAGE' | 'CVE';
        cves: string[];
        version: string | null;
        ecosystem: string | null;
    }
>;

export type GraphEdge = Refine<
    Schema<'GraphEdge'>,
    { source: string; target: string; relationship: string }
>;

export type DependencyGraph = Refine<
    Schema<'DependencyGraph'>,
    { nodes: GraphNode[]; edges: GraphEdge[] }
>;

export type TargetImpact = Refine<
    Schema<'TargetImpact'>,
    {
        targetId: number;
        targetKind: 'REPOSITORY' | 'CONTAINER';
        targetName: string;
        targetContext: string;
        sourceFile: string;
        packageName: string;
        packageVersion: string;
        reachability: string;
        scanId: number;
        cves: string[];
        purl: string | null;
    }
>;

export type TopImpactPackage = Refine<
    Schema<'TopImpactPackage'>,
    { packageName: string; ecosystem: string }
>;

export type BlastRadiusReport = Refine<
    Schema<'BlastRadiusReport'>,
    {
        query: string;
        queryType: 'PACKAGE' | 'CVE';
        targets: TargetImpact[];
        graph: DependencyGraph;
    }
>;

export type ThreatIntelRecord = Refine<
    Schema<'ThreatIntelRecord'>,
    {
        cveId: string;
        epssScore: number | null;
        epssPercentile: number | null;
        dateAdded: string | null;
        notes: string | null;
    }
>;

export type EpssPrioritizedIssue = Refine<
    Schema<'EpssPrioritizedIssue'>,
    {
        issueId: number;
        identifier: string;
        title: string;
        severity: string;
        reachability: string;
        targetName: string;
        targetKind: string;
        recommendedAction: string;
        priorityTier: 'CRITICAL_ARMED' | 'HIGH_PROBABLE' | 'MEDIUM_THEORETICAL' | 'LOW_PROBABILITY';
        cvssScore: number | null;
        epssScore: number | null;
        epssPercentile: number | null;
    }
>;

export type EpssFleetSummary = Refine<
    Schema<'EpssFleetSummary'>,
    { topPriorities: EpssPrioritizedIssue[]; breakdownByTier: Record<string, number> }
>;

export type NotificationChannelStatus = Refine<
    Schema<'NotificationChannelStatus'>,
    { type: string; name: string; destination: string; supportedEvents: string[] }
>;

export type NotificationTestResult = Refine<
    Schema<'NotificationTestResult'>,
    { type: string; message: string; testedAt: string }
>;

/** Ce que le modèle propose de faire, et ce qu'il propose de déclarer. Deux formes nommées. */
export type AiRemediationAdvice = Refine<
    Schema<'RemediationAdvice'>,
    { fixAction: string; suggestedVersion: string; codeSnippetOrDiff: string; cliCommand: string }
>;

export type AiVexSuggestion = Refine<
    Schema<'VexSuggestion'>,
    { status: string; justification: string; impactStatement: string; actionStatement: string }
>;

export type AiVulnerabilityAdvice = Refine<
    Schema<'AiVulnerabilityAdvice'>,
    {
        identifier: string;
        title: string;
        summaryExplanation: string;
        exploitMechanics: string;
        exposureAssessment: string;
        references: string[];
        remediation: AiRemediationAdvice;
        vexSuggestion: AiVexSuggestion;
    }
>;

/** How a dependency's licence sits with the target's, as the document enumerates it. */
export type LicenseCompatibility = 'COMPATIBLE' | 'CONDITIONAL' | 'INCOMPATIBLE_BLOCKING';

export type LicenseConflict = Refine<
    Schema<'LicenseConflict'>,
    {
        packageName: string;
        packageVersion: string;
        licenseExpression: string;
        riskCategory: LicenseRiskCategory;
        targetKind: string;
        targetName: string;
        compatibility: LicenseCompatibility;
        legalRiskExplanation: string;
        remediationAdvice: string;
    }
>;

export type CompatibilityCell = Refine<
    Schema<'CompatibilityCell'>,
    {
        targetLicenseType: string;
        dependencyLicenseCategory: string;
        compatibility: LicenseCompatibility;
        ruleDescription: string;
    }
>;

/** One point of the daily series: the day's open backlog, and its two movements. */
export type DailyPosturePoint = Refine<
    Schema<'DailyPosturePoint'>,
    { date: string; rollingMttrDays: number | null }
>;

/** One target on the maturity scoreboard, with the score the server computes. */
export type TargetMaturityScore = Refine<
    Schema<'TargetMaturityScore'>,
    {
        targetId: number;
        targetKind: string;
        targetName: string;
        maturityGrade: string;
        targetMttrDays: number | null;
    }
>;

export type PostureTrendAnalytics = Refine<
    Schema<'PostureTrendAnalytics'>,
    {
        mttrBySeverity: Record<string, number>;
        dailySeries: DailyPosturePoint[];
        targetScoreboard: TargetMaturityScore[];
        /** `null` when nothing was resolved in the window, and not zero. */
        overallMttrDays: number | null;
    }
>;

/** Who can reach it. The document types `visibility` as a plain `string` on this view. */
export type EndpointVisibility = 'PUBLIC' | 'INTERNAL' | 'UNKNOWN';

/**
 * What discovery concludes about an endpoint set against the declared contracts.
 *
 * `SHADOW_API` is the case that justifies the screen: a route being served that nothing documents.
 */
export type ShadowStatus = 'DOCUMENTED' | 'SHADOW_API' | 'UNDOCUMENTED' | 'HIGH_RISK_EXPOSURE';

export type ApiEndpointView = Refine<
    Schema<'EndpointView'>,
    {
        id: number;
        scanId: number;
        repositoryId: number;
        method: string;
        path: string;
        visibility: EndpointVisibility;
        shadowStatus: ShadowStatus;
        createdAt: string;
        authType: string | null;
        filePath: string | null;
        lineNumber: number | null;
        framework: string | null;
        operationId: string | null;
        summary: string | null;
        tags: string | null;
    }
>;

export type ApiContractView = Refine<
    Schema<'ApiContractEntity'>,
    {
        id: number;
        repositoryId: number;
        contractPath: string;
        endpointsCount: number;
        createdAt: string;
        scanId: number | null;
        format: string | null;
        title: string | null;
        version: string | null;
    }
>;

/** Six counts, all primitives: the document already marks every one of them always sent. */
export type AttackSurfaceSummary = Schema<'AttackSurfaceSummary'>;

export type RepositoryApisOverview = Refine<
    Schema<'RepositoryApisOverview'>,
    {
        repositoryId: number;
        endpoints: ApiEndpointView[];
        contracts: ApiContractView[];
        summary: AttackSurfaceSummary;
    }
>;

export type GlobalAttackSurface = Refine<
    Schema<'GlobalAttackSurface'>,
    {
        frameworks: string[];
        highRiskEndpoints: ApiEndpointView[];
        allEndpoints?: ApiEndpointView[];
    }
>;

export type ChangeType = 'ADDED' | 'REMOVED' | 'VERSION_CHANGED' | 'LICENSE_CHANGED' | 'UNCHANGED';

export type ComponentDelta = Refine<
    Schema<'ComponentDelta'>,
    {
        name: string;
        changeType: ChangeType;
        type: string | null;
        purl: string | null;
        oldVersion: string | null;
        newVersion: string | null;
        oldLicense: string | null;
        newLicense: string | null;
    }
>;

export type CveDelta = Refine<
    Schema<'CveDelta'>,
    {
        cveId: string;
        packageName: string;
        severity: string;
        status: NonNullable<Schema<'CveDelta'>['status']>;
        version: string | null;
    }
>;

export type SbomDiffReport = Refine<
    Schema<'SbomDiffReport'>,
    {
        fromScanId: number;
        toScanId: number;
        componentDeltas: ComponentDelta[];
        cveDeltas: CveDelta[];
        fromVersion: string | null;
        toVersion: string | null;
    }
>;

export type HighImpactFix = Refine<
    Schema<'HighImpactFix'>,
    {
        packageName: string;
        currentVersion: string;
        recommendedVersion: string;
        affectedCves: string[];
        affectedTargetNames: string[];
    }
>;

export type RemediationGap = Refine<Schema<'RemediationGap'>, { family: string }>;

export type RemediationCoverage = Refine<
    Schema<'RemediationCoverage'>,
    { gaps: RemediationGap[] }
>;

/** Tous les compteurs sont primitifs : seule la liste des correctifs demande une revendication. */
export type SecurityDebtReport = Refine<
    Schema<'SecurityDebtReport'>,
    { topHighImpactFixes: HighImpactFix[] }
>;

/** Les six natures de nœud d'un chemin, telles que le document les énumère. */
export type AttackPathNodeType = NonNullable<Schema<'AttackPathNode'>['type']>;

export type AttackPathNode = Refine<
    Schema<'AttackPathNode'>,
    {
        id: string;
        label: string;
        type: AttackPathNodeType;
        severity: string;
        subtitle?: string;
        metadata?: Record<string, string>;
    }
>;

export type AttackPathEdge = Refine<
    Schema<'AttackPathEdge'>,
    { id: string; source: string; target: string; label: string }
>;

/**
 * A path, not a node: it carries `riskLevel` and `isDirectlyExploitable`, never `severity` or
 * `isExploitable`. The two vocabularies live on the same screen, and confusing them in a fixture
 * was enough to have a tag render `undefined` for months.
 */
export type AttackPath = Refine<
    Schema<'AttackPath'>,
    {
        id: string;
        title: string;
        description: string;
        riskLevel: string;
        nodeIds: string[];
        remediationAdvice: string;
    }
>;

export type AttackPathGraph = Refine<
    Schema<'AttackPathGraph'>,
    {
        targetId: number;
        targetName: string;
        nodes: AttackPathNode[];
        edges: AttackPathEdge[];
        attackPaths: AttackPath[];
    }
>;

/* ------------------------------------------------------------------------- */
/* Preuve de processus : ce qui montre qu'un contrôle a fonctionné.           */
/*                                                                           */
/* Ces types portent des noms de champs en snake_case parce que le serveur    */
/* les publie ainsi : ils partent aussi dans un bundle de preuves qu'un       */
/* évaluateur ouvre à la main, et `target_kind` s'y lit mieux que             */
/* `targetKind`. Les recopier en camelCase ici aurait demandé une couche de   */
/* conversion dont le seul effet serait de faire diverger l'écran du fichier  */
/* que l'auditeur a sous les yeux.                                           */
/* ------------------------------------------------------------------------- */

export type RegisteredVerdict = Refine<
    Schema<'RegisteredVerdict'>,
    {
        id: string;
        target_kind: string;
        decided_at: string;
        counts_by_severity: Record<string, number>;
        target_id: number | null;
        fail_on_severity: string | null;
        policy_source: string | null;
        policy_version: number | null;
        decided_by: string | null;
    }
>;

export type VerdictRegister = Refine<
    Schema<'VerdictRegister'>,
    {
        verdicts: RegisteredVerdict[];
        /** Où reprendre, ou `null` à la fin du registre. */
        next_cursor: string | null;
    }
>;

export type ExceptionEntry = Refine<
    Schema<'ExceptionEntry'>,
    {
        issue_id: number;
        target_kind: string;
        decision: string;
        identifier: string | null;
        severity: string | null;
        target_id: number | null;
        target_name: string | null;
        justification: string | null;
        comment: string | null;
        actor: string | null;
        origin: string | null;
        decided_at: string | null;
        expires_at: string | null;
        last_reviewed_at: string | null;
        last_reviewed_by: string | null;
    }
>;

export type ExceptionsRegister = Refine<
    Schema<'Register'>,
    { entries: ExceptionEntry[]; next_cursor: string | null }
>;

export type ReviewOutcome = 'CONFIRMED' | 'EXTENDED' | 'REVOKED';

/**
 * Severity arrives lowercase, as everywhere else in this API.
 *
 * This route was the only one returning the Java enum as it stands — `CRITICAL` where the backlog
 * sends `critical`. A server-side view now spells it like the rest, and the union comes from the
 * document rather than from a list kept here.
 */
export type RemediationBySeverity = Refine<
    Schema<'BySeverityView'>,
    {
        severity: NonNullable<Schema<'BySeverityView'>['severity']>;
        percentageWithinSla: number | null;
        medianDays: number | null;
        ninetiethDays: number | null;
        oldestOpenDays: number | null;
    }
>;

export type RemediationDistribution = Refine<
    Schema<'RemediationDistributionView'>,
    {
        bySeverity: RemediationBySeverity[];
        oldestOpenDays: number | null;
        oldestOpenSeverity:
            | NonNullable<Schema<'RemediationDistributionView'>['oldestOpenSeverity']>
            | null;
    }
>;

export type RuleCoverageAssessment = Refine<
    Schema<'Assessment'>,
    {
        state: NonNullable<Schema<'Assessment'>['state']>;
        languagesWithRules: string[];
        ecosystemsInEstate: string[];
        uncovered: string[];
    }
>;

/** The four unions of an applicability declaration come from the document. */
export type Applicability = NonNullable<Schema<'Declaration'>['applicability']>;
export type Implementation = NonNullable<Schema<'Declaration'>['implementation']>;
export type EvidenceSource = NonNullable<Schema<'Declaration'>['evidenceSource']>;

/**
 * The gap between what an organisation declares and what this product measures.
 *
 * The document types `divergence` as a plain `string` on the row, so the list is kept here — and
 * `NOT_MEASURED_HERE` is the one that matters: it says no disagreement is observed *because
 * nothing was looked at*, which is not agreement.
 */
export type Divergence =
    | 'CONTRADICTED'
    | 'EXCLUDED_WITHOUT_JUSTIFICATION'
    | 'UNDECLARED'
    | 'OVERSTATED'
    | 'UNDERSTATED'
    | 'NOT_MEASURED_HERE'
    | 'NOT_APPLICABLE'
    | 'CONSISTENT';

export type ControlDeclaration = Refine<
    Schema<'Declaration'>,
    {
        /**
         * The framework's key, **and a string because it genuinely is one**.
         *
         * It was typed against the six compliance frameworks, which became false the moment the
         * OWASP Top 10 was declared in the same table — `OWASP_2021` is not one of them, and the
         * enum did not stop the value existing, it only stopped it being read.
         */
        framework: string;
        controlId: string;
        applicability: Applicability;
        evidenceSource: EvidenceSource;
        decidedAt: string;
        justification: string | null;
        implementation: Implementation | null;
        externalEvidence: string | null;
        owner: string | null;
        decidedBy: string | null;
        reviewedAt: string | null;
        reviewDueAt: string | null;
    }
>;

export type SoaLine = Refine<
    Schema<'Line'>,
    {
        control: ComplianceControl;
        declaration: ControlDeclaration | null;
        measured: ComplianceStatus | null;
        divergence: Divergence;
    }
>;

export type SoaStatement = Refine<
    Schema<'SoaStatement'>,
    {
        framework: ComplianceFramework;
        /** Le nom de la norme. `framework` est la constante Java, pas un libellé. */
        title: string;
        lines: SoaLine[];
    }
>;

export type DeclarationRequest = Refine<
    Schema<'DeclarationRequest'>,
    {
        applicability: Applicability;
        evidence_source: EvidenceSource;
        justification: string | null;
        implementation: Implementation | null;
        external_evidence: string | null;
        owner: string | null;
        review_due_at: string | null;
    }
>;

/** Five counts, all primitives — the document already marks every one of them always sent. */
export type ScopeCoverage = Schema<'ScopeCoverage'>;

/** A target of the certified scope, identified and qualified. */
export type ScopeTarget = Refine<Schema<'TargetRef'>, { kind: string; id: number }>;

export type ScopeView = Refine<
    Schema<'ScopeView'>,
    { statement: string; coverage: ScopeCoverage; targets: ScopeTarget[] }
>;

export type OwaspState = 'FINDINGS' | 'NOT_MEASURED' | 'NOT_COVERED' | 'NO_FINDING';

/**
 * One row of the grid, and what the organisation states about it.
 *
 * `declaration` is null until somebody says something — that permanent grey square is what the
 * declaration exists to remove. Two Top 10 categories are beyond any static analysis: leaving them
 * grey is honest and carries no review; declaring them says who asserts it, on what evidence, and
 * when it is looked at again.
 */
export type OwaspCoverageLine = Refine<
    Schema<'DeclaredCoverageLine'>,
    {
        id: string;
        title: string;
        state: OwaspState;
        because: string;
        declaration: ControlDeclaration | null;
    }
>;

/** `covered` dit combien des dix un scanner d'ici peut seulement regarder. **À lire avant le reste.** */
export type OwaspGrid = Refine<Schema<'DeclaredGrid'>, { lines: OwaspCoverageLine[] }>;

export type ComplianceMovement = NonNullable<Schema<'Step'>['movement']>;

export type ComplianceSnapshot = Refine<
    Schema<'ComplianceSnapshot'>,
    {
        period: string;
        framework: ComplianceFramework;
        status: ComplianceStatus;
        capturedAt: string;
    }
>;

export type ComplianceStep = Refine<
    Schema<'Step'>,
    {
        snapshot: ComplianceSnapshot;
        movement: ComplianceMovement;
        /** Une phrase, destinée à être citée sous le point. */
        because: string;
    }
>;

export type ComplianceSeries = Refine<
    Schema<'Series'>,
    { framework: ComplianceFramework; steps: ComplianceStep[] }
>;
