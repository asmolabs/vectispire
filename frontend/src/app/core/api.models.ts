/**
 * Les formes que rend l'API.
 *
 * **Écrites à la main, et pas encore remplaçables.** `npm run generate:api` produit
 * bien `api.generated.ts` depuis `/api/v1/openapi.json`, mais ce document ne décrit
 * aujourd'hui que les *chemins* : NestJS ne déclare un schéma de réponse que si le
 * contrôleur porte les décorateurs `@ApiResponse`/`@ApiOkResponse` et rend une classe
 * DTO. Sans eux, le générateur rend des opérations aux réponses vides — utiles pour
 * les URL, muettes sur les formes.
 *
 * Ce fichier disparaîtra donc quand les contrôleurs auront leurs DTO, et pas avant. Il
 * ne contient que des formes, aucune logique, pour que sa suppression soit alors sans
 * conséquence.
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

/** Ce que le dernier scan dit de la confiance qu'on peut accorder au verdict. */
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
     * Le verdict repose-t-il sur une observation réelle ? Une cible jamais scannée
     * produit un backlog vide, et un backlog vide passe toutes les politiques.
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

/** Un décompte groupé — une règle, un fichier ou un dépôt, et son nombre de constats. */
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

/** Un dépôt surveillé, avec l'état de son dernier scan. */
export interface MonitoredRepository {
    id: number;
    url: string;
    branch: string;
    name: string | null;
    /** Calculé par le serveur, pour que le même dépôt porte le même nom partout. */
    displayName: string;
    subPath: string | null;
    scanIntervalMinutes: number | null;
    scanCron: string | null;
    sshKeyId: string | null;
    lastScan: { id: number; status: string; createdAt: string | null; error: string | null } | null;
    openIssues: number;
}

export interface NewRepository {
    url: string;
    branch: string;
    name?: string;
    /** L'étiquette qu'un agent doit porter pour scanner cette cible. Vide : n'importe lequel. */
    required_agent_label?: string;
}

/** L'état d'un dernier scan, partagé par les dépôts et les conteneurs. */
export interface LastScan {
    id: number;
    status: string;
    createdAt: string | null;
    error: string | null;
}

/** Une image de conteneur surveillée. */
export interface MonitoredContainer {
    id: number;
    registry: string | null;
    imageName: string;
    tag: string;
    /** Calculée par le serveur : la forme qu'un registre attend. */
    reference: string;
    lastScan: LastScan | null;
    openIssues: number;
}

export interface NewContainer {
    registry?: string;
    image_name: string;
    tag: string;
    /** L'étiquette qu'un agent doit porter pour scanner cette cible. Vide : n'importe lequel. */
    required_agent_label?: string;
}

/** Où en est une clé privée vis-à-vis des clés de chiffrement configurées. */
export type EncryptionState = 'current' | 'previous_key' | 'unreadable';

/** Une clé de déploiement. La moitié privée n'apparaît jamais ici : le serveur ne la
 *  rend pas, et aucun écran n'aurait de raison de l'afficher. */
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

/** Un compte. L'empreinte du mot de passe n'y figure jamais : le serveur ne la rend
 *  pas, et une empreinte bcrypt qui sort du serveur est une empreinte à casser. */
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
    /** Pour ne pas proposer des actions que le serveur refusera de toute façon. */
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

/** Une clé d'API. La valeur en clair n'y figure pas : elle n'existe qu'une fois, dans la
 *  réponse à la création. */
export interface ApiKeySummary {
    id: string;
    name: string;
    /** Les douze premiers caractères, en clair. Ce n'est pas un secret. */
    prefix: string | null;
    scopes: string[];
    targetKind: string | null;
    targetId: number | null;
    targetLabel: string | null;
    createdAt: string | null;
    lastUsedAt: string | null;
    expiresAt: string | null;
    /** Calculé par le serveur : deux notions d'« expirée » divergeraient d'un fuseau. */
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
    /** La seule occurrence de la valeur en clair. Elle ne réapparaîtra jamais. */
    secret: string;
}

export interface ApiKeyTargets {
    repositories: { id: number; label: string }[];
    containers: { id: number; label: string }[];
}

/** Une entrée du journal d'audit. */
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

/** Le résultat de la vérification de la chaîne d'intégrité. */
export interface AuditVerification {
    total: number;
    /** Entrées antérieures au chaînage : ni une preuve ni une alerte. */
    unverifiable: number;
    verified: number;
    intact: boolean;
    broken: string | null;
}

/** Ce que montre le tableau de bord. Aucun de ces chiffres ne lui est propre : la
 *  posture vient de la même construction que l'écran Sécurité et que POST /gate. */
export interface DashboardOverview {
    posture: {
        failingCount: number;
        totalCount: number;
        kevCount: number;
        neverScannedCount: number;
        lastScanFailedCount: number;
    };
    /** Hors qualité, délibérément. */
    backlogBySeverity: Record<string, number>;
    /** À part, et jamais mêlé au backlog de sécurité : il ne bloque rien. */
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
    /** Ce que cet agent sait atteindre, séparé par des virgules. `null` : aucune cible étiquetée. */
    labels: string | null;
    /** A-t-il annoncé une clé publique éphémère ? Sinon, ses secrets voyagent en clair. */
    sealsCredentials: boolean;
    maxConcurrent: number | null;
    hostname: string | null;
    platform: string | null;
    version: string | null;
    contractVersion: string | null;
    lastSeenAt: string | null;
    /** Vu récemment — et non « activé ». Un agent activé mais muet est le cas qui compte. */
    online: boolean;
    runningScans: number;
}

export interface NewAgent {
    name: string;
    description?: string;
    credentials_mode: string;
    /** Séparées par des virgules. Ce que cet agent sait atteindre. */
    labels?: string;
    max_concurrent?: number;
}

/** Une étiquette exigée par des cibles qu'aucun agent activé ne porte. */
export interface UnroutableLabel {
    label: string;
    queued: number;
}

export interface IssuedAgent {
    id: string;
    name: string;
    /** La seule occurrence de la clé en clair. */
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
    hasSbom: boolean;
    findings: ScanFinding[];
    findingsTotal: number;
    /** La liste est-elle tronquée ? Le dire évite de croire le scan plus léger qu'il n'est. */
    findingsTruncated: boolean;
}

/**
 * Un réglage, tel que le serveur le décrit.
 *
 * Le type et l'explication viennent du serveur plutôt que d'être codés ici : ajouter un
 * réglage ne doit demander aucune modification de l'interface, et surtout l'écran ne doit
 * pas pouvoir proposer une clé qu'aucun service ne lit.
 */
export interface SettingDefinition {
    key: string;
    type: 'boolean' | 'integer' | 'text' | 'severity';
    section: string;
    label: string;
    help: string;
    default: string;
    value: string;
    /** A-t-elle été réglée, ou n'est-ce que le défaut ? Les deux ne se disent pas pareil. */
    configured: boolean;
}
