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
 * has a schema to lean on, and inventing one would be the same mistake in the other direction.
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

export type Refine<S, Claims extends { [K in keyof Claims]: K extends keyof S ? Claimable<S, K> : never }> = Omit<
    S,
    keyof Claims
> &
    Claims;

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
export type MfaSetupResponse = Refine<Schema<'SetupResponse'>, { secret: string; qrCodeUri: string; issuer: string }>;

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
        tlsCaPem: string | null;
        tlsCaSubject: string | null;
        tlsCaNotAfter: string | null;
    }
> & { authHeader?: string };

export type SiemTestResult = Refine<Schema<'TestResult'>, { message: string }>;

/**
 * Where FIRST's EPSS file stands. `scoreDate` is the day the scores in use are for, as the file says
 * — the age of the data — and a failed attempt leaves it where it was. Before the first
 * synchronisation no CVE has a score: unknown, which a screen must never show as zero.
 */
export type EpssFeedStatus = Refine<
    Schema<'EpssFeedStatus'>,
    {
        status: 'NEVER_SYNCED' | 'SYNCED' | 'FAILED';
        lastSyncedAt: string | null;
        modelVersion: string | null;
        scoreDate: string | null;
        lastAttemptAt: string | null;
        lastError: string | null;
    }
>;

/**
 * Where the CISA KEV catalogue stands, and the EPSS file under `epss`. `lastSyncedAt` is when the
 * catalogue in use was read, and a failed attempt leaves it where it was; `kevReleasedAt` is how old
 * that catalogue is, which a mirror refreshed rarely makes different.
 */
export type ThreatIntelSyncStatus = Refine<
    Schema<'ThreatIntelSyncStatus'>,
    {
        status: 'NEVER_SYNCED' | 'SYNCED' | 'FAILED';
        lastSyncedAt: string | null;
        kevCatalogVersion: string | null;
        kevReleasedAt: string | null;
        lastAttemptAt: string | null;
        lastError: string | null;
        epss: EpssFeedStatus;
    }
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
export type LicenseRiskCategory = 'PERMISSIVE' | 'WEAK_COPYLEFT' | 'STRONG_COPYLEFT' | 'FORBIDDEN' | 'UNKNOWN';

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

/** `NO_DATA` is no grade: nothing in the card's scope holds a completed scan, and its score is null. */
export type SecurityGrade = 'A_PLUS' | 'A' | 'B' | 'C' | 'D' | 'F' | 'NO_DATA';

/**
 * The target a project's or a solution's grade is read from — its weakest scanned one (decision
 * 0036), graded as its own card grades it — or the portfolio's weakest.
 */
export type ScorecardWeakestTarget = Refine<
    Schema<'WeakestTarget'>,
    { targetKind: string; targetName: string; grade: SecurityGrade }
>;

/**
 * `riskPoints` is the weighted open backlog the score is computed from — a sum, never a percentage —
 * and is `null` exactly when the score is. `weakestTarget` is a scope's alone.
 */
export type SecurityScorecard = Refine<
    Schema<'SecurityScorecard'>,
    {
        targetKind: string;
        targetName: string;
        grade: SecurityGrade;
        score: number | null;
        riskPoints: number | null;
        recommendations: string[];
        targetId: number | null;
        weakestTarget: ScorecardWeakestTarget | null;
    }
>;

/** How many of the reader's targets read one grade. */
export type PortfolioGradeCount = Refine<Schema<'GradeCount'>, { grade: SecurityGrade }>;

/**
 * The estate the reader sees, with no grade of its own since 0.11.0: the distribution of its
 * targets' grades (every grade, `NO_DATA` included, in the scale's order), the weakest target —
 * `null` when none is scanned — and the risk points of everything open.
 */
export type PortfolioScorecard = Refine<
    Schema<'PortfolioScorecard'>,
    { grades: PortfolioGradeCount[]; weakestTarget: ScorecardWeakestTarget | null }
>;

export type BadgeState = Refine<Schema<'BadgeState'>, { token: string | null; url: string | null }>;

export type PinnedSigningKey = Refine<Schema<'PinnedSigningKey'>, { id: string; privateKey: string | null }>;

/** What produced the result, and what it is about. */
export type AttestationBuilder = Refine<Schema<'Builder'>, { id: string; version: string }>;

export type AttestationSubject = Refine<Schema<'Subject'>, { name: string; digest: Record<string, string> }>;

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

export type AttestationPolicy = Refine<Schema<'PolicyAssessment'>, { violations: string[]; enforcedPolicy: string }>;

/** The seven counters are primitives: the document marks them all as always sent. */
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
 * with `IssueView`, which carries neither; the detail route sends `IssueDetail`. Declaring one
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
        /**
         * Where a `plugin` or `imported` issue came from (decision 0017): `tool` is the key that
         * scopes its resolution (`plugin:<id>`, `import:<source>/<tool>`), `toolName` and
         * `toolVersion` what the report's driver said, `importSource` the declared source's slug —
         * kept after the source is deleted. All four null for what Vectispire's own scanners found.
         */
        tool: string | null;
        toolName: string | null;
        toolVersion: string | null;
        importSource: string | null;
    }
>;

/**
 * What a triage or a ticket attachment answers with: the stored issue, without the remediation
 * window the backlog query computes and without the target's resolved name. Call sites use it to
 * read back what the server accepted — a trimmed ticket reference, a refused one — and then
 * reload.
 */
export type TriagedIssue = Refine<
    Schema<'IssueView'>,
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
    /** Leaves out what triage settled — `not_affected`, `fixed` — as the dashboard's figures do,
     *  so a count and the list it opens agree. */
    unsettled?: boolean;
    triage_status?: string;
    repository_id?: number;
    container_id?: number;
    /** The repositories filed in that project at request time, over what the reader may see;
     *  containers never match. A project the reader sees nothing of answers an empty page. */
    project_id?: number;
    /** The same, over every project of the solution. Combines with `project_id`: both apply. */
    solution_id?: number;
    only_direct?: boolean;
    search?: string;
    /** The weekly OWASP view's drill-down: a category as the grid places it (`A01`…`A10`), or `any` of them. */
    owasp_category?: string;
    /** Open at the end of that day, UTC — what a week's open count counts at its Sunday. */
    open_at?: string;
    /** ISO days, `_to` included. With any date and no `state`, the server lists every state. */
    first_seen_from?: string;
    first_seen_to?: string;
    resolved_from?: string;
    resolved_to?: string;
    /** Reopened in that range, by a reopening the triage history recorded. */
    reopened_from?: string;
    reopened_to?: string;
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
export type OverviewPolicy = Refine<Schema<'OverviewPolicyView'>, { source: string; version: number | null }>;

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

/** The copy-and-paste verification commands the crypto route offers; only the manifest one is shown today. */
export interface CosignCliHelper {
    commands?: { cosignVerifyManifest?: string };
}

/** What ingesting a VEX document reports back. */
export interface VexIngestResult {
    triagedIssues?: number;
    appliedCves?: string[];
}

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
        /** The schedule in force as the server decides it, the installation's default included. */
        schedule?: ScheduleInForce | null;
        /** The label an agent must carry to scan this target. Sent by the server all along. */
        requiredAgentLabel: string | null;
        sshKeyId: string | null;
        /** The managed HTTPS token this repository clones with; never set together with `sshKeyId`. */
        httpsTokenId: string | null;
        lastScan: LastScan | null;
        tier?: AssetTier;
        /**
         * What its newest completed scan counted. **`null` is unknown, `[]` is "counted, none"** —
         * never scanned since the count existed, or the walk stopped at its bound. Rendering both
         * alike would say "no language" of a tree nobody has looked at.
         */
        detectedLanguages: DetectedLanguage[] | null;
    }
>;

/** A language counted in a repository, spelt as a plugin manifest declares it, so the two compare as strings. */
export type DetectedLanguage = NonNullable<Schema<'RepositorySummary'>['detectedLanguages']>[number];

export interface NewRepository {
    url: string;
    branch: string;
    name?: string;
    subPath?: string;
    scanIntervalMinutes?: number | null;
    scanCron?: string;
    /** Absent leaves it alone; true clears the interval and the expression, and is refused beside either. */
    scanManualOnly?: boolean;
    required_agent_label?: string;
    tier?: AssetTier;
    /** Absent leaves the key alone on update; the empty string detaches it. */
    sshKeyId?: string;
    /** Same rule as `sshKeyId`, and the server's own spelling — snake case, unlike its neighbour. */
    https_token_id?: string;
}

/**
 * The schedule in force on a repository or an image: `manual`, `cron`, `interval` or `default`, and
 * the interval it runs at under the last two — null for a cron expression, for manual only, and for
 * the default when the installation has none.
 */
export type ScheduleInForce = Refine<
    Schema<'ScheduleInForce'>,
    { mode: 'manual' | 'cron' | 'interval' | 'default'; intervalMinutes: number | null }
>;

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
        schedule?: ScheduleInForce | null;
        requiredAgentLabel: string | null;
        lastScan: LastScan | null;
        tier?: AssetTier;
        /** Null when the image is in no project; `projectName` is then null too ("Solution / Project" otherwise). */
        projectId?: number | null;
        projectName?: string | null;
    }
>;

export interface NewContainer {
    registry?: string;
    image_name: string;
    tag: string;
    scanIntervalMinutes?: number | null;
    scanCron?: string;
    scanManualOnly?: boolean;
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

/**
 * A managed HTTPS clone token. The secret never appears here, for the same reason the private half
 * of an SSH key does not: the server does not return it once stored.
 *
 * `host` is the one host the token may be sent to (decision 0022). A repository whose URL names
 * another host is refused, so the token cannot be walked to a server that would collect it.
 */
export type GitTokenSummary = Refine<
    Schema<'GitTokenSummary'>,
    {
        id: string;
        name: string;
        host: string;
        username: string | null;
        createdAt: string;
        encryptionState: EncryptionState;
    }
>;

export type NewGitToken = Refine<Schema<'GitTokenCreateRequest'>, { name: string; host: string; token: string }>;

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

export type NewUser = Refine<Schema<'UserCreateRequest'>, { username: string; password: string; role: string }>;

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
export type TeamSummary = Refine<Schema<'TeamSummary'>, { id: number; name: string; description: string | null }>;

export type TeamTargetAssignment = Refine<Schema<'TeamTargetAssignment'>, { kind: string; id: number }>;

/**
 * A target an account sees directly, without going through a team.
 *
 * The same shape as {@link TeamTargetAssignment} and still distinct — the control plane names them
 * separately too. The two sets add up server-side, and merging them into one type is how a screen
 * comes to replace one believing it replaces the other.
 */
export type UserTargetAssignment = Refine<Schema<'UserTargetAssignment'>, { kind: string; id: number }>;

/**
 * A grant as the server reads it back, **named by the server**.
 *
 * The write side stays `{ kind, id }`; the read side carries the name because a project grant
 * names something the picker's repository and image lists do not hold — "Solution / Project" —
 * and a grant the dialog cannot label is a grant it shows as nothing, then drops on save.
 * `kind` is `repository`, `container` or `project`; left a string so a fourth kind is shown raw
 * rather than refused.
 */
export type TargetGrant = Refine<Schema<'TargetGrant'>, { kind: string; id: number; name: string | null }>;

/** Open issues by severity, over what the reader may see — settled triage left out. */
export type OpenIssues = Schema<'OpenIssues'>;

export type RepositoryRef = Refine<Schema<'RepositoryRef'>, { id: number; name: string }>;

/** A container image in the tree, named as every other screen names a target (`TargetNaming`). */
export type ContainerRef = Refine<Schema<'ContainerRef'>, { id: number; name: string }>;

/** A project in the tree. `partial` says the reader sees only some of its repositories. */
export type ProjectNode = Refine<
    Schema<'ProjectNode'>,
    {
        id: number;
        solutionId: number;
        name: string;
        description: string | null;
        openIssues: OpenIssues;
        repositories: RepositoryRef[];
        /** Optional: a control plane from before images were filed sends none, which is "none". */
        containers?: ContainerRef[];
        /** The union over the repositories the reader sees; it speaks only for those not in `languagesUnknownFor`. */
        detectedLanguages: DetectedLanguage[];
        /** The visible repositories whose languages are unknown. */
        languagesUnknownFor: number[];
    }
>;

export type SolutionNode = Refine<
    Schema<'SolutionNode'>,
    { id: number; name: string; description: string | null; openIssues: OpenIssues; projects: ProjectNode[] }
>;

/** The repositories and images in no project: a group of its own, never left out of the tree. */
export type Unfiled = Refine<
    Schema<'Unfiled'>,
    { openIssues: OpenIssues; repositories: RepositoryRef[]; containers?: ContainerRef[] }
>;

/** `GET /api/v1/solutions` — decision 0023. */
export type SolutionTree = Refine<Schema<'SolutionTree'>, { solutions: SolutionNode[]; unfiled: Unfiled }>;

export type SolutionRef = Refine<Schema<'SolutionRef'>, { id: number; name: string }>;

/** `GET /api/v1/projects/{id}` — the tree's node, read on its own, with the solution it is filed in. */
export type ProjectDetail = Refine<
    Schema<'ProjectDetail'>,
    {
        id: number;
        solutionId: number;
        name: string;
        description: string | null;
        openIssues: OpenIssues;
        repositories: RepositoryRef[];
        containers?: ContainerRef[];
        detectedLanguages: DetectedLanguage[];
        languagesUnknownFor: number[];
        solution: SolutionRef;
    }
>;

/**
 * `GET /api/v1/{projects,solutions}/{id}/compliance` — the estate summary and the portfolio
 * scorecard, computed over the scope's visible targets. `partial` says some are hidden from the
 * reader; `targetCount` is how many were counted.
 */
export type ScopeCompliance = Refine<
    Schema<'ScopeCompliance'>,
    { kind: string; name: string; compliance: ComplianceSummary; scorecard: SecurityScorecard }
>;

/**
 * What a target's last scan says of its inventory. `absent` (no SBOM produced) and `never_scanned`
 * are not an empty list: a consolidated list missing them is incomplete, not clean (decision 0007).
 */
export type InventoryState = NonNullable<Schema<'TargetInventory'>['inventory']>;

export type TargetInventory = Refine<
    Schema<'TargetInventory'>,
    { kind: string; name: string; inventory: InventoryState; scanId: number | null; scannedAt: string | null }
>;

export type ComponentTarget = Refine<Schema<'ComponentTarget'>, { kind: string; name: string }>;

export type MergedComponent = Refine<
    Schema<'MergedComponent'>,
    { name: string; version: string | null; purl: string | null; type: string | null; targets: ComponentTarget[] }
>;

/** `GET /api/v1/projects/{id}/components` — `complete` is false while a visible target lists nothing. */
export type ConsolidatedInventory = Refine<
    Schema<'ConsolidatedInventory'>,
    { kind: string; name: string; targets: TargetInventory[]; components: MergedComponent[] }
>;

export type SolutionView = Refine<Schema<'SolutionView'>, { id: number; name: string; description: string | null }>;

export type ProjectView = Refine<
    Schema<'ProjectView'>,
    { id: number; solutionId: number; name: string; description: string | null }
>;

/** A target a key may be scoped to, as the picker needs it: identified and named. */
export type TargetOption = Refine<Schema<'TargetOption'>, { id: number; label: string }>;

export type ApiKeyTargets = Refine<Schema<'Targets'>, { repositories: TargetOption[]; containers: TargetOption[] }>;

/** An audit log entry. Everything but its identity can be absent, and is sent as `null`. */
export type AuditEntry = Refine<
    Schema<'AuditEntryView'>,
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
        /**
         * The day, an ISO date in UTC, this installation's grades changed formula (decision 0036) —
         * `null` where there was no grade to change. The chart marks it when it falls in the window.
         */
        score_formula_changed_on: string | null;
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

export type NewAgent = Refine<Schema<'AgentCreateRequest'>, { name: string; credentials_mode: string }>;

export type UnroutableLabel = Refine<Schema<'UnroutableLabel'>, { label: string }>;

/** The credentialed scans nobody able to be handed their credential can take; `''` is "no label". */
export type UnservedCredentialedScans = Refine<
    Schema<'UnservedCredentialedScans'>,
    { scans: number; labels: string[]; keptAgents: string[] }
>;

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
        /** For a waiting scan whose last attempt could not run, when it may be claimed again. */
        notBefore: string | null;
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
        /** Set for a plugin's findings: `plugin:<id>`, and what the report's driver said it was. */
        tool: string | null;
        toolName: string | null;
        toolVersion: string | null;
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
        /**
         * Each plugin of the scan in one of its three states; empty for a scan that ran none. A
         * plugin the scan should have run and that is missing here was not examined — the list is
         * not a claim that everything expected ran.
         */
        plugins: PluginOutcome[];
        /**
         * The built-in finding types whose step produced in this scan, as wire names. `null` is
         * "not recorded" — a scan from before the control plane kept it, or one that never ran —
         * and never "examined nothing", which is the empty list.
         */
        examinedTypes: string[] | null;
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

/**
 * The 409 a rule-set change answers when it would resolve open issues and `acceptLosing` is not
 * their current number: `affectedIssues` is that number, read at the refusal — the one to confirm.
 */
export type RuleSetLosesIssuesProblem = Schema<'RuleSetLosesIssuesProblem'>;

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
        /**
         * `manual`, `approval` or `review` — somebody's; `expiry` — a deadline passed; `reopen` — a
         * scan or an import found the resolved issue again.
         */
        origin: string;
        justification: string | null;
        comment: string | null;
        /** Null when nobody decided: a deadline passed, or the issue was reopened. See `origin`. */
        actor: string | null;
        expiresAt: string | null;
        scanId: number | null;
        version: string | null;
        /** On a reopening only: when the resolution it ended began. Null on every decision. */
        previousResolvedAt: string | null;
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
export type InventoryResults = Refine<Schema<'Results'>, { occurrences: InventoryOccurrence[] }>;

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
        /** `running` while another request waits for the model: a review is recorded before it is asked. */
        status: 'completed' | 'failed' | 'running';
        /** The model that wrote it: comparing two reports without knowing this is a trap. */
        model: string;
        /** The model's answer as it came. Kept so nothing renders a report the raw text contradicts. */
        content: string | null;
        blocks: OwaspBlock[];
        error: string | null;
        /** The scan it was built from — what dates it and names the version it describes. */
        scanId: number;
        /**
         * What the model was shown, kept beside what it answered.
         *
         * **This is what makes the report traceable rather than merely dated.** The prompt is a
         * static instruction; the evidence digest is the half that decides what the prose says, and
         * it cannot be recomputed later because the issues it was built from have moved on.
         */
        inputs: string | null;
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
        sightings: IssueSighting[];
        decisions: HistoryDecision[];
        /** The provenance of a `plugin` or `imported` issue — see {@link Issue}. */
        tool: string | null;
        toolName: string | null;
        toolVersion: string | null;
        importSource: string | null;
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
 *
 * `include_plugins` is the same kind of late field, and **absent reads as off** on the server. The
 * form did not send it, so a policy saved with plugin findings switched on would have been stored
 * with them off, under a version number claiming somebody chose that. It is claimed here, so a
 * form that forgets it no longer compiles.
 */
export type GatePolicyRequest = Refine<
    Schema<'PolicyRequest'>,
    {
        fail_on_severity: string;
        fail_on_kev: boolean;
        fixable_only: boolean;
        include_triaged: boolean;
        include_ai_review: boolean;
        include_plugins: boolean;
        fail_on_uncovered_languages: boolean;
        note: string | null;
    }
>;

/** The category a control belongs to, as the document enumerates it. */
export type ComplianceCategory = Schema<'ComplianceControl'>['category'];

/**
 * A control's verdict, and the framework's own. One vocabulary for both. `NO_DATA` is no verdict:
 * nothing of the estate was observed, and the score beside it (zero) is no measurement.
 */
export type ComplianceStatus = 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'NO_DATA';

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
        gateStatus: 'PASSED' | 'FAILED' | 'NEVER_SCANNED' | 'LAST_SCAN_FAILED' | 'SCANNING' | 'IN_PROGRESS';
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

export type GraphEdge = Refine<Schema<'GraphEdge'>, { source: string; target: string; relationship: string }>;

export type DependencyGraph = Refine<Schema<'DependencyGraph'>, { nodes: GraphNode[]; edges: GraphEdge[] }>;

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
        scanId: number;
        cves: string[];
        purl: string | null;
    }
>;

export type TopImpactPackage = Refine<Schema<'TopImpactPackage'>, { packageName: string; ecosystem: string }>;

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
        targetName: string;
        targetKind: string;
        recommendedAction: NonNullable<Schema<'EpssPrioritizedIssue'>['recommendedAction']>;
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

/**
 * What the model proposes to do, and what it proposes to declare. Two named shapes.
 *
 * `suggestedVersion` is null when no fixed version is recorded: it read "the fixed version", a
 * version nobody had said existed, printed as the target of the upgrade.
 */
export type AiRemediationAdvice = Refine<
    Schema<'RemediationAdvice'>,
    { fixAction: string; suggestedVersion: string | null; codeSnippetOrDiff: string; cliCommand: string }
>;

export type AiVexSuggestion = Refine<
    Schema<'VexSuggestion'>,
    { status: string; justification: string; impactStatement: string; actionStatement: string }
>;

/**
 * The values the product's own wording was built from.
 *
 * Always sent, and null when unknown: the component, its version and the fixed version were filled
 * with words that read as values — "the component", "current", "the latest fixed version" — and
 * `kev` was a boolean that said false before any catalogue had been read. `UNKNOWN` and a null
 * `exploitProbability` are what the screen says when nothing answered.
 */
export type AiDeterministic = Refine<
    Schema<'Deterministic'>,
    {
        packageName: string | null;
        currentVersion: string | null;
        targetVersion: string | null;
        kev: NonNullable<Schema<'Deterministic'>['kev']>;
        exploitProbability: number | null;
    }
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
        /**
         * Set when the product wrote the prose itself, absent when a model did.
         *
         * The sentences above stay free text because a model fills them with its own, in whatever
         * language it chose. What the server can say is who wrote them: when this is present, every
         * sentence was built from exactly these values, and the screen rebuilds them in the
         * reader's language instead of printing the English fallback.
         */
        deterministic?: AiDeterministic;
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
        /**
         * What the licence means here, as a token the screen turns into two sentences.
         *
         * The explanation and the advice used to arrive as French sentences and were printed as
         * they stood, under headers that went through the bundle. One token rather than two
         * fields: the server never chooses them separately, and two fields would have allowed a
         * pair that says one thing and advises another.
         */
        verdict: NonNullable<Schema<'LicenseConflict'>['verdict']>;
    }
>;

export type CompatibilityCell = Refine<
    Schema<'CompatibilityCell'>,
    {
        targetLicenseType: string;
        dependencyLicenseCategory: string;
        compatibility: LicenseCompatibility;
        note: NonNullable<Schema<'CompatibilityCell'>['note']>;
    }
>;

/** One point of the daily series: the day's open backlog, and its two movements. */
export type DailyPosturePoint = Refine<Schema<'DailyPosturePoint'>, { date: string; rollingMttrDays: number | null }>;

/**
 * One target on the maturity scoreboard: the score and grade of its scorecard, the ones its card and
 * its badge show. A target holding no completed scan carries maturityGrade 'NO_DATA' and a null
 * securityScore, and ranks last.
 */
export type TargetMaturityScore = Refine<
    Schema<'TargetMaturityScore'>,
    {
        targetId: number;
        targetKind: string;
        targetName: string;
        maturityGrade: SecurityGrade;
        securityScore: number | null;
        /** The card's risk points; `null` exactly when the score is. Ties in score rank by them. */
        riskPoints: number | null;
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
    Schema<'ApiContractView'>,
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

export type RemediationCoverage = Refine<Schema<'RemediationCoverage'>, { gaps: RemediationGap[] }>;

/** Tous les compteurs sont primitifs : seule la liste des correctifs demande une revendication. */
export type SecurityDebtReport = Refine<Schema<'SecurityDebtReport'>, { topHighImpactFixes: HighImpactFix[] }>;

/** The six kinds of node on a path, as the document enumerates them. */
export type AttackPathNodeType = NonNullable<Schema<'AttackPathNode'>['type']>;

export type AttackPathNode = Refine<
    Schema<'AttackPathNode'>,
    {
        id: string;
        label: string;
        type: AttackPathNodeType;
        severity: string;
        /** What the node is, as a token; the sentence is in the bundles. */
        note: NonNullable<Schema<'AttackPathNode'>['note']>;
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
        /**
         * Which scenario this is; the title, the narrative and the plan follow from it.
         *
         * The three used to arrive as French sentences with the method, the path and the package
         * concatenated into them on the server. The values that vary now travel in {@link params},
         * because a concatenation is what a translation cannot reorder.
         */
        scenario: NonNullable<Schema<'AttackPath'>['scenario']>;
        params: Record<string, string>;
        riskLevel: string;
        nodeIds: string[];
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
/* Process evidence: what shows that a control ran.                          */
/*                                                                           */
/* These types carry snake_case field names because the server publishes     */
/* them that way: they also travel in an evidence bundle an assessor opens   */
/* by hand, and `target_kind` reads better there than `targetKind`.          */
/* Restating them in camelCase here would have needed a conversion layer     */
/* whose only effect would be to make the screen diverge from the file the   */
/* auditor has in front of them.                                             */
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
        /** Where to resume, or `null` at the end of the register. */
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

export type ExceptionsRegister = Refine<Schema<'Register'>, { entries: ExceptionEntry[]; next_cursor: string | null }>;

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
        oldestOpenSeverity: NonNullable<Schema<'RemediationDistributionView'>['oldestOpenSeverity']> | null;
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
    | 'UNEVIDENCED'
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
        /** The standard's name. `framework` is the Java constant, not a label. */
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

/** `covered` says how many of the ten a scanner here can even look at. **Read before the rest.** */
export type OwaspGrid = Refine<Schema<'DeclaredGrid'>, { lines: OwaspCoverageLine[] }>;

/**
 * One category in one week of `GET /api/v1/owasp/coverage/weekly`.
 *
 * `state` and `settled` are `null` on a reconstructed week — the record holds nothing for it, and
 * the server never computes a state now for then. `state` is `null` too on a recorded week whose
 * targets left no line for the category: "not recorded", which is not "nothing found".
 */
export type OwaspWeekCategory = Refine<
    Schema<'OwaspWeekCategory'>,
    { category: string; title: string; state: OwaspState | null; settled: number | null; reopened: number | null }
>;

/**
 * One ISO week, Monday 00:00 UTC to the next. **`open` does not mean the same thing on both
 * kinds of week**: recorded, it leaves settled triage out and `settled` carries it apart;
 * reconstructed, it counts every issue open at the week's end whatever its triage, and `settled`
 * is `null` because the triage of a past date is not known.
 */
export type OwaspWeek = Refine<
    Schema<'OwaspWeek'>,
    {
        weekStart: string;
        capturedAt: string | null;
        categoriesMeasured: number | null;
        settled: number | null;
        /** `null` on a week that began before reopenings were recorded: not zero, not known. */
        reopened: number | null;
        categories: OwaspWeekCategory[];
    }
>;

/** The project or solution asked for; `partial` says the reader sees only `targetCount` of its targets. */
export type OwaspWeeklyScope = Refine<Schema<'OwaspWeeklyScope'>, { kind: string; name: string }>;

export type OwaspWeeklyCoverage = Refine<
    Schema<'OwaspWeeklyCoverage'>,
    {
        from: string;
        to: string;
        scope: OwaspWeeklyScope | null;
        /** The Monday of the first week whose `reopened` is known; `null` when none is. */
        reopenedRecordedFrom: string | null;
        weeks: OwaspWeek[];
    }
>;

/** The query string of the weekly view; absent values are left to the server's defaults. */
export interface OwaspWeeklyQuery {
    from?: string;
    to?: string;
    project_id?: number;
    solution_id?: number;
}

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
        /** One sentence, meant to be quoted under the item. */
        because: string;
    }
>;

export type ComplianceSeries = Refine<Schema<'Series'>, { framework: ComplianceFramework; steps: ComplianceStep[] }>;

/**
 * A language a plugin can declare — the Semgrep catalogue's directories, read from the document so a
 * language added on the server reaches the form without being retyped here.
 */
export type PluginLanguage = NonNullable<Schema<'PluginManifest'>['languages']>[number];

/**
 * A plugin's manifest (decision 0017), **as the governor wrote it and the server stored it.**
 *
 * The id enters every issue fingerprint the plugin produces, and the digest the server computes
 * covers every field, so nothing here is cosmetic: an argument edited is a new manifest.
 */
export type PluginManifest = Refine<
    Schema<'PluginManifest'>,
    {
        id: string;
        name: string;
        /** `repository@sha256:<64 hex>`, never a tag. */
        image: string;
        languages: PluginLanguage[];
        arguments: string[];
        output: string | null;
        exit_codes: number[];
        network_justification: string | null;
        /** Null: the scanner limits' own timeout. */
        timeout_seconds: number | null;
        /** Who must have signed the image; null trusts it by its digest alone. */
        signature: PluginSignature | null;
    }
>;

/**
 * Who a plugin's image must be signed by — keyless (identity and issuer, matched exactly) or a public
 * key, exactly one of the two. **The server is the judge of which**: the form sends what was typed.
 */
export type PluginSignature = Refine<
    Schema<'PluginSignature'>,
    { identity: string | null; issuer: string | null; public_key: string | null }
>;

/** A registered plugin: the manifest it runs now, and who registered and last changed it. */
export type Plugin = Refine<
    Schema<'PluginView'>,
    {
        id: string;
        name: string;
        manifest: PluginManifest;
        manifestDigest: string;
        createdAt: string | null;
        createdBy: string | null;
        updatedAt: string | null;
        updatedBy: string | null;
        /** The governor's waiver of the signature requirement; null for none. */
        unsignedWaiver: PluginUnsignedWaiver | null;
    }
>;

/** Running a plugin although its manifest declares no signer, decided in writing by the governor. */
export type PluginUnsignedWaiver = Refine<
    Schema<'UnsignedWaiver'>,
    { justification: string; waivedBy: string | null; waivedAt: string | null }
>;

/**
 * A plugin switched on for one project, named as grants name it. The names are null only when the
 * project was deleted between the activation's read and its naming.
 */
export type PluginActivation = Refine<
    Schema<'PluginActivationView'>,
    {
        id: number;
        pluginId: string;
        projectId: number;
        projectName: string | null;
        solutionId: number | null;
        solutionName: string | null;
        activatedAt: string | null;
        activatedBy: string | null;
    }
>;

/**
 * The ends of a plugin's step (`PluginOutcome.State`), enumerated by the document.
 * **`not_applicable` is not a failure and `absent` is** — the screens must not blur the two, because
 * one of them is somebody's problem and the other would be noise on every scan. **`refused` is a
 * failure too, of another kind**: the executor would not start the plugin for want of a verified
 * signer (decision 0017 §9.1), and the remedy is its provenance, not its code.
 */
export type PluginState = NonNullable<Schema<'PluginOutcome'>['state']>;

/**
 * Why an executor would not start a plugin: `unsigned`, `signature_unverified`, or
 * `registry_authentication_required` — the registry would not let the signature be read.
 */
export type PluginRefusal = NonNullable<Schema<'PluginOutcome'>['refusal']>;

/** The footing a produced plugin ran on: `verified`, `waived` or `not_required`. */
export type PluginSignatureFooting = NonNullable<Schema<'PluginOutcome'>['signature']>;

export type PluginOutcome = Refine<
    Schema<'PluginOutcome'>,
    {
        pluginId: string;
        manifestDigest: string | null;
        state: PluginState;
        /** Produced only: how many findings the report carried. */
        findings: number | null;
        /** Not applicable only: the languages it looked for and did not find. */
        languages: string[];
        /** Absent or refused: why no usable report came back, or why it was not started. */
        reason: string | null;
        /** Refused only; null for a reason this version does not know — still a refusal. */
        refusal: PluginRefusal | null;
        /** Produced only; null for a scan from before the field. */
        signature: PluginSignatureFooting | null;
    }
>;

/**
 * What a declared source may deliver (decision 0032 §7). The contract types them as strings; these
 * are the values `SourceKind.wireName()` spells, and a key must hold `sarif_import` for the first and
 * `report_import` for the two others.
 */
export type SourceKind = 'sarif' | 'coverage' | 'test_report';

/** In the order the form offers them: SARIF first, since a source without kinds is SARIF alone. */
export const SOURCE_KINDS: readonly SourceKind[] = ['sarif', 'coverage', 'test_report'];

/**
 * A declared internal source (decisions 0017 §7, 0032 §7): one integration key, exactly one scope —
 * a project or a repository, never both, never the estate — the kinds of report it may deliver and,
 * when SARIF is among them, the tools it may deliver. `tools` is empty for a source without SARIF.
 */
export type SarifSource = Refine<
    Schema<'SarifSourceView'>,
    {
        id: number;
        slug: string;
        name: string;
        apiKeyId: string;
        /** Null once the key is revoked: the source stays declared, and delivers nothing until re-keyed. */
        apiKeyName: string | null;
        projectId: number | null;
        repositoryId: number | null;
        tools: string[];
        kinds: SourceKind[];
        createdAt: string | null;
        createdBy: string | null;
    }
>;

/**
 * The body declaring a source. Exactly one of `project_id` and `repository_id`; `kinds` never empty
 * (the server refuses a source delivering nothing), and `tools` empty unless SARIF is among them.
 */
export type SarifSourceDeclaration = Refine<
    Schema<'SourceDeclaration'>,
    {
        slug: string;
        name: string;
        api_key_id: string;
        tools: string[];
        kinds: SourceKind[];
    }
>;

/**
 * One accepted coverage report (decision 0032 §7): a figure a checklist reads, never a finding.
 * `branchesCovered`/`branchesTotal` are null when the report counted no branch; `commit` and
 * `branch` are what the pipeline stated, verified against nothing.
 */
export type CoverageImport = Refine<
    Schema<'CoverageImportView'>,
    {
        id: number;
        sourceId: number | null;
        sourceSlug: string;
        repoId: number;
        format: string;
        toolVersion: string | null;
        branchesCovered: number | null;
        branchesTotal: number | null;
        commit: string | null;
        branch: string | null;
        documentSha256: string;
        importedAt: string;
        importedBy: string | null;
        apiKeyId: string | null;
        /**
         * `kept` when the report's counts per package were kept beside its totals; why not otherwise; null
         * for an import accepted before packages were kept — a rule scoped to packages needs it re-imported.
         */
        packagesState?: 'kept' | 'too_many' | 'path_refused' | 'inconsistent' | null;
    }
>;

/** One accepted test report, its totals counted from the test cases; the suites are not listed. */
export type TestReportImport = Refine<
    Schema<'TestReportImportView'>,
    {
        id: number;
        sourceId: number | null;
        sourceSlug: string;
        repoId: number;
        format: string;
        commit: string | null;
        branch: string | null;
        documentSha256: string;
        importedAt: string;
        importedBy: string | null;
        apiKeyId: string | null;
    }
>;

/**
 * One accepted import: the imported issue's dated evidence, where a scanned issue has its scan.
 * `tools` is the report's tools, one `name version` each, in the report's order.
 */
export type SarifImport = Refine<
    Schema<'SarifImportView'>,
    {
        id: number;
        sourceId: number | null;
        sourceSlug: string;
        repoId: number;
        tools: string[];
        documentSha256: string;
        importedAt: string;
        importedBy: string | null;
        apiKeyId: string | null;
    }
>;

/**
 * Where a checklist template version stands (decision 0032 §3, §4) — `TemplateVersionStatus.wireName()`.
 * A draft is being confirmed and nobody answers it; a published version is immutable; a retired one
 * opens no new checklist, and a draft set aside is retired too, never having been published.
 */
export type ChecklistVersionStatus = 'draft' | 'published' | 'retired';

/** What became of one item between the previous published version and this one (decision 0032 §4). */
export type ChecklistChange = 'unchanged' | 'changed' | 'added' | 'removed';

/** The columns a layout names — `ChecklistColumn.wireName()`; control, answer and comment are required. */
export type ChecklistColumn = 'id' | 'domain' | 'objective' | 'control' | 'contact' | 'kpi' | 'answer' | 'comment';

/** The header entries a layout may name — `HeaderCell.Field.wireName()`, each only when the template has it. */
export type ChecklistHeaderField = 'date' | 'product' | 'author';

/**
 * A template version without its items. `revision` is the draft's edit counter, which publishing
 * names; `draftAuthors` are the usernames that imported, derived, confirmed or paired it — with
 * four-eyes on, none of them may publish or retire it.
 */
export type ChecklistVersionSummary = Refine<
    Schema<'ChecklistVersionSummary'>,
    {
        id: number;
        label: string | null;
        status: ChecklistVersionStatus;
        sourceSha256: string;
        previousOrdinal: number | null;
        derivedFromOrdinal: number | null;
        draftAuthors: string[];
        importedAt: string;
        importedBy: string | null;
        publishedAt: string | null;
        publishedBy: string | null;
        retiredAt: string | null;
        retiredBy: string | null;
    }
>;

/** A checklist template and its versions, oldest first, without their items. */
export type ChecklistTemplate = Refine<
    Schema<'ChecklistTemplateView'>,
    {
        id: number;
        slug: string;
        name: string;
        createdAt: string;
        createdBy: string | null;
        versions: ChecklistVersionSummary[];
    }
>;

/** A header entry: the label cell the renderer leaves alone and the value cell it writes (`B3`). */
export type ChecklistHeaderCell = Refine<Schema<'HeaderCellForm'>, { label: string; value: string }>;

/** The template's own words for yes and no, and for not applicable when the version offers it. */
export type ChecklistAnswerWords = Refine<
    Schema<'AnswerWordsForm'>,
    { yes: string; no: string; notApplicable: string | null }
>;

/**
 * A layout as the importer confirms it and as the API shows it back. Sent whole: the server refuses,
 * in words, any part a layout cannot be.
 */
export type ChecklistLayout = Refine<
    Schema<'ChecklistLayoutForm'>,
    {
        sheet: string;
        columns: Partial<Record<ChecklistColumn, string>>;
        firstItemRow: number;
        lastItemRow: number;
        header: Partial<Record<ChecklistHeaderField, ChecklistHeaderCell>>;
        answers: ChecklistAnswerWords;
    }
>;

/** One line of a version: the template's words as imported, its key and its content digest. */
export type ChecklistItem = Refine<
    Schema<'ChecklistItemView'>,
    {
        id: number;
        itemKey: string;
        position: number;
        domain: string | null;
        objective: string | null;
        control: string;
        contact: string | null;
        kpi: string | null;
        contentDigest: string;
        sheetRow: number;
        evidenceKind: ChecklistEvidenceKind;
        evidenceValidityMonths: number | null;
        boundRule: ChecklistRule | null;
    }
>;

/** "The added item is the removed one, reworded" — both named by their keys as the preview shows them. */
export type ChecklistItemPair = Refine<Schema<'ChecklistItemPair'>, { added: string; removed: string }>;

/**
 * What proof one line of a draft is to ask for, named by its key as the version shows it. The
 * validity is 1 to 120 months, or null for a proof that does not expire — always null on `none`.
 */
export type ChecklistItemEvidence = Refine<
    Schema<'ChecklistItemEvidence'>,
    { itemKey: string; evidenceKind: ChecklistEvidenceKind; evidenceValidityMonths: number | null }
>;

/** One version whole: its summary, its confirmed layout (null until confirmed), its items and pairs. */
export type ChecklistVersion = Refine<
    Schema<'ChecklistVersionView'>,
    {
        templateSlug: string;
        templateName: string;
        version: ChecklistVersionSummary;
        layout: ChecklistLayout | null;
        items: ChecklistItem[];
        pairs: ChecklistItemPair[];
    }
>;

/** One cell of the sheet as the reader sees it; `formula` marks a value recalculated at every opening. */
export type ChecklistPreviewCell = Refine<Schema<'PreviewCell'>, { ref: string; column: string; text: string }>;

/**
 * Where the reader thinks the checklist is, found from the workbook's structure and never from its
 * words. Any part it could not find is left out — null — for the importer to name.
 */
export type ChecklistProposedLayout = Refine<
    Schema<'ProposedLayout'>,
    {
        sheet: string;
        columnHeaderRow: number | null;
        firstItemRow: number | null;
        lastItemRow: number | null;
        columns: Partial<Record<ChecklistColumn, string>>;
        header: Partial<Record<ChecklistHeaderField, ChecklistHeaderCell>>;
        answerValues: string[];
    }
>;

/**
 * One item's fate against the previous version. `readKey` is the new item's key as the layout read
 * it — what a pair names as `added`; `previousKey` is what a pair names as `removed`.
 */
export type ChecklistPairingChange = Refine<
    Schema<'PairingChange'>,
    {
        change: ChecklistChange;
        readKey: string | null;
        row: number | null;
        control: string | null;
        previousKey: string | null;
        previousRow: number | null;
        previousControl: string | null;
    }
>;

/** What the importer looks at before confirming: the proposal, the confirmed layout, a sheet, the pairing. */
export type ChecklistPreview = Refine<
    Schema<'ChecklistTemplatePreview'>,
    {
        templateSlug: string;
        version: ChecklistVersionSummary;
        sheets: string[];
        sheet: string;
        cells: ChecklistPreviewCell[];
        proposal: ChecklistProposedLayout;
        layout: ChecklistLayout | null;
        pairing: ChecklistPairingChange[];
    }
>;

/**
 * Where a revision of a project's checklist stands (decision 0032 §5) — `ChecklistStatus.wireName()`.
 * A draft is answered; a submitted one waits for a sign-off or a return; a signed-off one is never
 * modified again, only reopened as the next revision; a superseded one is an open revision set aside
 * by a move to another version.
 */
export type ChecklistStatus = NonNullable<Schema<'ChecklistRevisionSummary'>['status']>;

/** An answer, `ChecklistAnswer.wireName()`; `not_applicable` only on a version that offers it. */
export type ChecklistAnswerValue = NonNullable<Schema<'ChecklistAnswerView'>['value']>;

/**
 * What keeps a line from a submission, in the order a person fixes them — `ProjectChecklistService.problems`,
 * the judgement the submission itself makes: on a draft, `measurement_contradicted` for a "yes" against a
 * failing measurement, and a comment and a proof for a "yes" where there is no data. A proof is asked of
 * a "yes" only.
 */
export type ChecklistLineProblem = NonNullable<Schema<'ChecklistLineView'>['problems']>[number];

/** What a line asks as proof of a "yes" — `EvidenceRequirement.Kind.wireName()`. */
export type ChecklistEvidenceKind = NonNullable<Schema<'ChecklistLineView'>['evidenceKind']>;

/**
 * One revision as a listing shows it. `edition` counts its writes: every write names the edition
 * the person read, and the server refuses one that is stale.
 */
export type ChecklistRevisionSummary = Refine<
    Schema<'ChecklistRevisionSummary'>,
    {
        status: ChecklistStatus;
        templateSlug: string;
        templateName: string;
        versionLabel: string | null;
        author: string;
        openedAt: string;
        openedBy: string;
        supersedesRevision: number | null;
        submittedAt: string | null;
        submittedBy: string | null;
        returnedAt: string | null;
        returnedBy: string | null;
        returnReason: string | null;
        signedOffAt: string | null;
        signedOffBy: string | null;
        signOffFourEyes: boolean | null;
        supersededAt: string | null;
        supersededBy: string | null;
    }
>;

/**
 * One answer as given, a row of the line's history. A carried copy keeps the author and instant of
 * the answer it came from and names who carried it; `needsConfirmation` marks one carried onto a
 * line that changed.
 */
export type ChecklistAnswer = Refine<
    Schema<'ChecklistAnswerView'>,
    {
        id: number;
        itemId: number;
        value: ChecklistAnswerValue;
        comment: string | null;
        answeredBy: string;
        answeredAt: string;
        measurementId: number | null;
        carriedFromId: number | null;
        carriedBy: string | null;
        carriedAt: string | null;
        edition: number;
    }
>;

/** A proof: a link, or a file known by its name, size and digest — its bytes only as a download. */
export type ChecklistEvidence = Refine<
    Schema<'ChecklistEvidenceView'>,
    {
        id: number;
        itemId: number;
        kind: 'link' | 'file';
        link: string | null;
        fileName: string | null;
        mediaType: string | null;
        fileSize: number | null;
        fileSha256: string | null;
        performedOn: string;
        validUntil: string | null;
        addedBy: string;
        addedAt: string;
        carriedFromId: number | null;
        edition: number;
        withdrawnBy: string | null;
        withdrawnAt: string | null;
    }
>;

/**
 * One line: the template's words, the rule it is measured by (null for none), the current answer (null
 * while unanswered), its proofs and its problems. On a draft, `problems` include what the line's
 * measurement keeps from a submission, judged as the submission judges it — so the view's
 * `readyToSubmit` is what the submission will say, unless something changes first.
 */
export type ChecklistLine = Refine<
    Schema<'ChecklistLineView'>,
    {
        itemId: number;
        itemKey: string;
        position: number;
        domain: string | null;
        objective: string | null;
        control: string;
        contact: string | null;
        kpi: string | null;
        evidenceKind: ChecklistEvidenceKind;
        evidenceValidityMonths: number | null;
        rule: ChecklistRule | null;
        answer: ChecklistAnswer | null;
        evidence: ChecklistEvidence[];
        problems: ChecklistLineProblem[];
    }
>;

/** The template's own words, as the importer mapped them; `notApplicable` null when not offered. */
export type ChecklistWords = Refine<
    Schema<'AnswerWordsView'>,
    { yes: string; no: string; notApplicable: string | null }
>;

/**
 * One revision whole. `authors` are everybody who wrote it — with four-eyes on, none of them signs
 * it off; `fourEyesRequired` is the setting now. Both are for a hint: the server decides.
 */
export type ChecklistView = Refine<
    Schema<'ChecklistView'>,
    {
        checklist: ChecklistRevisionSummary;
        projectName: string;
        answerWords: ChecklistWords;
        authors: string[];
        lines: ChecklistLine[];
    }
>;

/** Every answer and every proof of one line, oldest first, withdrawn proofs included. */
export type ChecklistLineHistory = Refine<
    Schema<'ChecklistLineHistory'>,
    { answers: ChecklistAnswer[]; evidence: ChecklistEvidence[] }
>;

/**
 * A published template version a project's checklist may be opened on or moved to — `unrenderable` set
 * on one no sign-off could fill in (published before the publication's trial rendering), which the
 * server refuses to open on or move to, and `null` on every other.
 */
export type ChecklistOfferedVersion = Refine<
    Schema<'ChecklistOfferedVersion'>,
    {
        templateSlug: string;
        templateName: string;
        label: string | null;
        publishedAt: string;
        unrenderable: ChecklistVersionUnrenderable | null;
    }
>;

/**
 * Why no checklist opens on, or moves to, an offered version: the trial rendering's English sentence, and
 * the cells at fault — empty when the reason is not a formula in a cell a sign-off writes.
 */
export type ChecklistVersionUnrenderable = Refine<
    Schema<'ChecklistVersionUnrenderable'>,
    { detail: string; cells: ChecklistUnrenderableCell[] }
>;

/**
 * What a project's checklist page shows before it has a checklist: the project's name, and where its
 * newest revision stands — both null while it has none, which is the edition opening one names.
 */
export type ChecklistProjectContext = Refine<
    Schema<'ChecklistProjectContext'>,
    { projectName: string; latestRevision: number | null; latestEdition: number | null }
>;

/**
 * One line a `checklist-incomplete` refusal names, in the problem's `lines` extension member
 * (`ChecklistIncompleteProblem`). `problems` are a line's own tokens — never `measurement_contradicted`,
 * which refuses under a cause of its own.
 */
export type ChecklistIncompleteLine = Refine<
    Schema<'IncompleteLine'>,
    { problems: Exclude<ChecklistLineProblem, 'measurement_contradicted'>[] }
>;

/**
 * One cell a `checklist-template-unrenderable` or `checklist-version-unrenderable` refusal names, in the
 * problem's `cells` member (`ChecklistUnrenderableProblem`): a cell a sign-off writes that carries a
 * formula other cells depend on — `shared`, the master of a shared formula, or `array`, an array formula.
 */
export type ChecklistUnrenderableCell = Refine<
    Schema<'UnrenderableCell'>,
    { cell: string; kind: 'shared' | 'array'; range: string }
>;

// ---------------------------------------------------------------------- measured lines (decision 0032 §6)

/** What a line is measured by — `ChecklistRule.Kind.wireName()`. */
export type ChecklistRuleKind = NonNullable<Schema<'ChecklistRuleForm'>['kind']>;

/** The severities a threshold names — `Severity.wireName()`. */
export type ChecklistSeverity = NonNullable<Schema<'MeasuredFigure'>['severity']>;

/** What one severity may still hold: at most so many open, at least such a share resolved — one or both. */
export type ChecklistThreshold = Refine<
    Schema<'ThresholdForm'>,
    { maxOpen?: number | null; minResolvedRatio?: number | null }
>;

/**
 * One package an organisation requires, by package-URL prefix, and — on a `component_versions` rule — the
 * versions of it it allows, exact or Maven ranges; a `component_present` rule names the prefix alone.
 */
export type ChecklistAllowedComponent = Refine<
    Schema<'ComponentForm'>,
    { purlPrefix: string; versions?: string[] | null }
>;

/**
 * The packages a coverage rule measures: matched by an `include` pattern — every package when none is
 * given — and by no `exclude` pattern. Patterns over package paths (`org/example/service`), `**` whole
 * segments, `*` characters within one.
 */
export type ChecklistCoverageScope = Refine<
    Schema<'CoverageScopeForm'>,
    { include?: string[] | null; exclude?: string[] | null }
>;

/**
 * A rule as the binding route reads it and as a line's view shows it — one shape for every kind, each
 * kind taking its own fields; an item's `boundRule` and a measurement's are this shape too. The server refuses a key another kind takes, so the client sends only the kind's own
 * and leaves the others out; a rule read back may carry them as null.
 */
export type ChecklistRule = Refine<
    Schema<'ChecklistRuleForm'>,
    {
        kind: ChecklistRuleKind;
        maxAgeDays: number;
        requireSchedule?: boolean | null;
        scopes?: string[] | null;
        thresholds?: Partial<Record<ChecklistSeverity, ChecklistThreshold>> | null;
        metric?: 'line' | 'branch' | null;
        minimumRatio?: number | null;
        aggregation?: 'per_repository' | 'project_weighted' | null;
        suitePattern?: string | null;
        minimumTests?: number | null;
        components?: ChecklistAllowedComponent[] | null;
        scope?: ChecklistCoverageScope | null;
    }
>;

/** One line of a draft to bind, named by its key as the version shows it; a null rule unbinds it. */
export type ChecklistItemRule = Refine<Schema<'ChecklistItemRule'>, { itemKey: string; rule: ChecklistRule | null }>;

/** `MeasurementOutcome.wireName()`: no data is never a pass. */
export type MeasurementOutcome = NonNullable<Schema<'ChecklistMeasurementView'>['outcome']>;

/** Why a measurement has no data — `NoDataReason.wireName()`, a closed set. */
export type NoDataReason = NonNullable<Schema<'ChecklistMeasurementView'>['reason']>;

/** An answer beside its line's measurement — `Reconciliation.wireName()`. */
export type Reconciliation = NonNullable<Schema<'MeasuredLineView'>['reconciliation']>;

/**
 * What a measurement keeps from a submission — `ProjectChecklistService.measurements`: a yes against a
 * failure, or what a yes where there is no data still needs (question 4).
 */
export type MeasuredLineProblem = NonNullable<Schema<'MeasuredLineView'>['problems']>[number];

/** What a measurement read — `MeasurementFacts.Source.wireName()`. */
export type MeasurementSource = NonNullable<Schema<'RepositoryLook'>['source']>;

/** A repository's look: `examined`, `not_applicable`, or the no-data reason it lacks data for. */
export type RepositoryLookStatus = NonNullable<Schema<'RepositoryLook'>['status']>;

/**
 * One repository's contribution. `repositoryName` is the repository as every screen names it — null
 * for one no longer in the project, or gone, which a stored measurement may still cite: fall back to
 * its id. `source` and what follows it are null when nothing was read. `detail` is the server's English.
 */
export type RepositoryLook = Refine<
    Schema<'RepositoryLook'>,
    {
        repositoryName: string | null;
        scope: string | null;
        status: RepositoryLookStatus;
        source: MeasurementSource | null;
        sourceId: number | null;
        at: string | null;
        digest: string | null;
        met: boolean | null;
        detail: string | null;
    }
>;

/** Issues of one severity in one scope — or, under `all`, the total a threshold was judged on. */
export type MeasuredFigure = Refine<
    Schema<'MeasuredFigure'>,
    { scope: string; severity: ChecklistSeverity; met: boolean | null; detail: string | null }
>;

/** The evidence as judged. `summary` is one English sentence, for the audit entry and the document. */
export type MeasurementEvidence = Refine<
    Schema<'MeasurementEvidence'>,
    { summary: string; repositories: RepositoryLook[]; figures: MeasuredFigure[] }
>;

/**
 * What a rule found for one line. One computed for this read has a null `id` and the purpose `read`;
 * `evidenceDigest` is what an answer resting on it names.
 */
export type ChecklistMeasurement = Refine<
    Schema<'ChecklistMeasurementView'>,
    {
        id: number | null;
        itemId: number;
        purpose: 'read' | 'answer' | 'submission' | 'sign_off';
        ruleKind: ChecklistRuleKind;
        ruleDigest: string;
        boundRule: ChecklistRule;
        outcome: MeasurementOutcome;
        reason: NoDataReason | null;
        asOf: string | null;
        computedAt: string;
        computedBy: string | null;
        answerId: number | null;
        answerValue: ChecklistAnswerValue | null;
        reconciliation: Reconciliation;
        evidenceDigest: string;
        evidence: MeasurementEvidence;
    }
>;

/** One bound line of a revision, its measurement beside its answer. */
export type MeasuredLine = Refine<
    Schema<'MeasuredLineView'>,
    {
        itemKey: string;
        rule: ChecklistRule;
        answer: ChecklistAnswerValue | null;
        answerId: number | null;
        measurement: ChecklistMeasurement | null;
        atSubmission: ChecklistMeasurement | null;
        reconciliation: Reconciliation;
        problems: MeasuredLineProblem[];
    }
>;

/**
 * The measured lines of a revision. `live`: computed for this read — a draft's or a submitted one's —
 * rather than read back as the sign-off froze them; `computedAt` is null when nothing was computed.
 */
export type ChecklistMeasurements = Refine<
    Schema<'ChecklistMeasurementsView'>,
    { status: ChecklistStatus; computedAt: string | null; lines: MeasuredLine[] }
>;

/**
 * One line a `checklist-measurement-contradicted` or `checklist-measurement-changed` refusal names, in
 * the problem's `lines` member (`ChecklistMeasurementProblem`): its answer, what the rule finds now and,
 * for a sign-off, what it found at the submission.
 */
export type ChecklistMeasuredConflictLine = Refine<
    Schema<'MeasuredLine'>,
    {
        answer: ChecklistAnswerValue | null;
        outcome: MeasurementOutcome;
        reason: NoDataReason | null;
        submittedOutcome: MeasurementOutcome | null;
        submittedReason: NoDataReason | null;
    }
>;

/** Why the as-measured act left a line alone — `AsMeasuredSkipReason.wireName()`. */
export type AsMeasuredSkipReason = NonNullable<Schema<'AsMeasuredSkip'>['reason']>;

/** One line the as-measured act answered: a yes, resting on the measurement stored with it. */
export type ChecklistAsMeasuredAnswer = Refine<Schema<'AsMeasuredAnswer'>, { value: 'yes'; evidenceDigest: string }>;

/**
 * One measured line the act left alone, with why and what it measures now; `answer` is the one it
 * already had, if any.
 */
export type ChecklistAsMeasuredSkip = Refine<
    Schema<'AsMeasuredSkip'>,
    {
        reason: AsMeasuredSkipReason;
        outcome: MeasurementOutcome;
        noDataReason: NoDataReason | null;
        evidenceDigest: string;
        answer: ChecklistAnswerValue | null;
    }
>;

/**
 * What `POST …/answers/as-measured` answers: the checklist as it now is — its edition moved on only
 * when a line was answered — the lines answered, and every measured line left alone.
 */
export type ChecklistAsMeasured = Refine<
    Schema<'ChecklistAsMeasuredView'>,
    { checklist: ChecklistView; answered: ChecklistAsMeasuredAnswer[]; skipped: ChecklistAsMeasuredSkip[] }
>;

/** One line the screen offered the one click on, with the digest of the measurement it showed. */
export type ChecklistShownMeasurement = Refine<
    Schema<'ShownMeasurement'>,
    { itemId: number; measurementDigest: string }
>;

/**
 * The closed list of what a report plugin may write (decision 0035 §3) — HTML, the legacy binary
 * Office formats and macro-enabled packages are not on it.
 */
export type ReportMediaType = NonNullable<Schema<'ReportPluginManifest'>['media_type']>;

/**
 * A report plugin's manifest (decision 0035 §2), **as the governor pasted it and the server stored
 * it.** The digest covers every field, so nothing here is cosmetic. `signature` is required with no
 * waiver: the platform signs what the image writes and does not lend its key to an image nobody
 * vouched for.
 */
export type ReportPluginManifest = Refine<
    Schema<'ReportPluginManifest'>,
    {
        id: string;
        name: string;
        image: string;
        export_schema: number;
        arguments: string[];
        output: string;
        media_type: ReportMediaType;
        signature: PluginSignature;
    }
>;

/**
 * Where a manifest digest stands: `pending_approval`, `approved`, `superseded` — replaced before
 * anybody approved it, never ran — and `withdrawn`, final.
 */
export type ReportManifestStatus = NonNullable<Schema<'ReportPluginManifestView'>['status']>;

/** One manifest of a report plugin, by digest: who registered, approved and withdrew it. */
export type ReportPluginManifestView = Refine<
    Schema<'ReportPluginManifestView'>,
    {
        digest: string;
        status: ReportManifestStatus;
        manifest: ReportPluginManifest;
        registeredAt: string | null;
        registeredBy: string | null;
        approvedAt: string | null;
        approvedBy: string | null;
        /** Whether four-eyes applied to its approval; null until approved. */
        approvalFourEyes: boolean | null;
        withdrawnAt: string | null;
        withdrawnBy: string | null;
        withdrawalJustification: string | null;
    }
>;

/**
 * A registered report plugin. `approvedDigest` is the one a run uses, `pendingDigest` the one awaiting
 * a second person; either may be null. `manifests` is every digest it ever had, newest first.
 */
export type ReportPlugin = Refine<
    Schema<'ReportPluginView'>,
    {
        id: string;
        name: string;
        approvedDigest: string | null;
        pendingDigest: string | null;
        createdAt: string | null;
        createdBy: string | null;
        updatedAt: string | null;
        updatedBy: string | null;
        manifests: ReportPluginManifestView[];
    }
>;

/** A report plugin switched on for one project. `pluginName` is null only when the plugin row could not be read. */
export type ReportPluginActivation = Refine<
    Schema<'ReportPluginActivationView'>,
    {
        id: number;
        pluginId: string;
        pluginName: string | null;
        projectId: number;
        activatedAt: string | null;
        activatedBy: string | null;
    }
>;

/** `pending`, `running`, `produced`, `failed`, `refused` — `ReportRunState`. */
export type ReportRunState = NonNullable<Schema<'ReportRunView'>['state']>;

/**
 * Why a run did not produce — `ReportRunReason`, closed. A refusal (`unsigned`, `signature_unverified`,
 * `registry_authentication_required`, `export_schema_unavailable`, `output_refused`) is how a tampered
 * plugin shows itself; a failure is work going wrong.
 */
export type ReportRunReason = NonNullable<Schema<'ReportRunView'>['reason']>;

/**
 * One report run of a project. Everything after `requestedAt` is null until the step that records it:
 * the manifest and signer at the claim, the export once built, the output and the package once
 * produced. `reason` and `detail` only for a run that did not produce.
 */
export type ReportRun = Refine<
    Schema<'ReportRunView'>,
    {
        id: number;
        projectId: number;
        projectName: string | null;
        pluginId: string;
        state: ReportRunState;
        reason: ReportRunReason | null;
        detail: string | null;
        requestedAt: string | null;
        requestedBy: string | null;
        startedAt: string | null;
        exportedAt: string | null;
        finishedAt: string | null;
        manifestDigest: string | null;
        imageDigest: string | null;
        signerIdentity: string | null;
        signerIssuer: string | null;
        signerKeySha256: string | null;
        exportSchemaVersion: string | null;
        exportSha256: string | null;
        exportSize: number | null;
        exitCode: number | null;
        outputSize: number | null;
        outputSha256: string | null;
        outputMediaType: string | null;
        signingKeyId: string | null;
        packageSha256: string | null;
        productVersion: string | null;
        /**
         * Set once the platform governor withdrew the manifest the run used (decision 0035 §4): its document
         * is still served, but the installation no longer stands by it. Null while the manifest stands.
         */
        withdrawnAt: string | null;
        withdrawnBy: string | null;
        withdrawalJustification: string | null;
    }
>;

/** Where a forge discovery stands (decision 0037 §3) — the document's own enum. */
export type ForgeDiscoveryState = NonNullable<Schema<'ForgeDiscoveryView'>['state']>;

/** Why a discovery ended `partial` or `failed` — the document's own enum. */
export type ForgeDiscoveryReason = NonNullable<Schema<'ForgeDiscoveryView'>['reason']>;

/**
 * One discovery of a forge connection. The counters are primitives the document marks required; the
 * comparison's counts are `null` until the run ended, and `goneCount` stays `null` unless it completed —
 * a partial listing proves nothing about what it did not reach (decision 0007).
 */
export type ForgeDiscovery = Refine<
    Schema<'ForgeDiscoveryView'>,
    {
        connectionId: string;
        state: ForgeDiscoveryState;
        reason: ForgeDiscoveryReason | null;
        detail: string | null;
        requestedAt: string;
        requestedBy: string | null;
        startedAt: string | null;
        finishedAt: string | null;
        rateLimitResetAt: string | null;
        newCount: number | null;
        changedCount: number | null;
        goneCount: number | null;
    }
>;

/**
 * A read-only connection to a forge. Never the token. `scopes` and `canWrite` are `null` when the forge
 * does not report them — a GitHub fine-grained token — which is *unknown*, never *read-only*.
 */
export type ForgeConnection = Refine<
    Schema<'ForgeConnectionView'>,
    {
        id: string;
        name: string;
        kind: string;
        edition: string;
        baseUrl: string;
        owner: string | null;
        credentialKind: string | null;
        scopes: string[] | null;
        canWrite: boolean | null;
        tokenExpiresAt: string | null;
        forgeVersion: string | null;
        caSubject: string | null;
        caNotAfter: string | null;
        encryptionState: EncryptionState;
        lastDiscovery: ForgeDiscovery | null;
        createdAt: string;
        createdBy: string | null;
    }
>;

/** One repository of a discovery's snapshot. A value the forge did not give is `null`: unknown, never zero. */
export type ForgeRepository = Refine<
    Schema<'ForgeRepositoryView'>,
    {
        forgeId: string;
        fullPath: string;
        namespacePath: string;
        name: string;
        defaultBranch: string | null;
        archived: boolean | null;
        fork: boolean | null;
        visibility: string | null;
        language: string | null;
        lastActivityAt: string | null;
        sizeBytes: number | null;
        webUrl: string | null;
        changeSummary: string | null;
    }
>;

/** `GET …/discoveries/{id}/repositories` — one page of a discovery's comparison. */
export type ForgeRepositoryPage = Refine<Schema<'RepositoryPage'>, { items: ForgeRepository[] }>;

/** Why a repository is not offered, or was skipped by an import — the document's own enum. */
export type ForgeSkipReason = NonNullable<Schema<'ForgeSkippedImport'>['reason']>;

/** One row of the selection table. */
export type ForgeCandidate = Refine<
    Schema<'ForgeCandidate'>,
    {
        repository: ForgeRepository;
        notSelectable: ForgeSkipReason | null;
        presentAs: number[] | null;
        importedAs: number | null;
        proposedSolution: string | null;
        proposedProject: string | null;
    }
>;

/** `GET …/selection` — `unjudged` counts, per filter, the repositories it could not judge. */
export type ForgeCandidatePage = Refine<
    Schema<'ForgeCandidatePage'>,
    { items: ForgeCandidate[]; unjudged: Record<string, number> | null }
>;

/** The selection as the server answers it: what stays ticked, and the ids it could not tick. */
export type ForgeSelection = Refine<Schema<'ForgeSelection'>, { selected: string[]; dropped: string[] | null }>;

/** The filters of the selection table, as the query and the selection's body both spell them. */
export type ForgeSelectionFilters = Schema<'ForgeSelectionFilters'>;

/** The body of a preview and of an import: the same, so that what was previewed is what is imported. */
export type ForgeImportRequest = Schema<'ForgeImportRequest'>;

/** A credential the preview proposes or the request chose: `ssh_key`, `https_token` or `none`. */
export type ForgeCredentialView = Refine<
    Schema<'ForgeCredentialView'>,
    { kind: string; id: string | null; name: string | null }
>;

export type ForgePlannedTarget = Refine<
    Schema<'ForgePlannedTarget'>,
    {
        forgeId: string;
        fullPath: string;
        url: string;
        branch: string | null;
        credential: ForgeCredentialView;
        solution: string | null;
        project: string | null;
        firstScanNotBefore: string | null;
        warning: string | null;
    }
>;

export type ForgeSkippedImport = Refine<
    Schema<'ForgeSkippedImport'>,
    { forgeId: string; fullPath: string; reason: ForgeSkipReason; repositoryIds: number[] | null }
>;

export type ForgeRefusedImport = Refine<
    Schema<'ForgeRefusedImport'>,
    { forgeId: string; fullPath: string; refusal: string }
>;

export type ForgeHostCredential = Refine<
    Schema<'ForgeHostCredential'>,
    { host: string; credential: ForgeCredentialView }
>;

export type ForgeProjectPlan = Refine<
    Schema<'ForgeProjectPlan'>,
    { name: string; solution: string; existingId: number | null }
>;

export type ForgeSolutionPlan = Refine<Schema<'ForgeSolutionPlan'>, { name: string; existingId: number | null }>;

export type ForgeFirstScans = Refine<Schema<'ForgeFirstScans'>, { firstAt: string | null; lastAt: string | null }>;

/** `POST …/imports/preview` — what the import would do, nothing written. */
export type ForgeImportPreview = Refine<
    Schema<'ForgeImportPreview'>,
    {
        targets: ForgePlannedTarget[];
        skipped: ForgeSkippedImport[];
        refused: ForgeRefusedImport[];
        solutions: ForgeSolutionPlan[];
        projects: ForgeProjectPlan[];
        credentials: ForgeHostCredential[];
        firstScans: ForgeFirstScans | null;
        visibilityMode: string;
    }
>;

export type ForgeImportedTarget = Refine<
    Schema<'ForgeImportedTarget'>,
    {
        forgeId: string;
        fullPath: string;
        url: string;
        solution: string | null;
        project: string | null;
        firstScanId: number | null;
        firstScanNotBefore: string | null;
    }
>;

/** `POST …/imports` — what the import created and skipped. */
export type ForgeImportResult = Refine<
    Schema<'ForgeImportResult'>,
    {
        created: ForgeImportedTarget[];
        skipped: ForgeSkippedImport[];
        solutionsCreated: string[];
        projectsCreated: string[];
        firstScans: ForgeFirstScans | null;
    }
>;
