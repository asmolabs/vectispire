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
