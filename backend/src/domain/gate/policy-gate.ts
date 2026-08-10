/**
 * Verdict passé/échoué du backlog d'une cible face à une politique.
 *
 * C'est ce qui rend Zanshin utilisable depuis un pipeline plutôt que seulement
 * depuis un navigateur : un job CI demande « au vu de ce que vous savez de cette
 * cible, cette compilation doit-elle échouer ? » et reçoit un verdict motivé.
 *
 * Fonctions pures sur une liste de problèmes — pas de HTTP, pas de session — pour que
 * la sémantique soit testable exhaustivement, et que la même évaluation serve
 * l'endpoint `POST /api/v1/gate`, le badge de l'écran Sécurité et le seuil des
 * notifications. Réimplémenter la règle en SQL pour l'un des trois la ferait diverger
 * au premier drapeau ajouté.
 *
 * Décisions qui méritent d'être énoncées, reprises telles quelles de l'implémentation
 * Python :
 *
 * - **Un problème trié ne fait pas échouer une compilation par défaut.** Un jugement
 *   `not_affected` argumenté est la raison d'être du triage ; un gate qui l'ignore
 *   renvoie les équipes à désactiver le gate. `includeTriaged` existe pour le cas
 *   d'audit où l'on veut l'image brute.
 * - **« Corrigeable uniquement » est proposé, et n'est pas le défaut.** N'échouer que
 *   sur ce qui a un correctif publié est le réglage pragmatique, mais en défaut il
 *   tolérerait en silence une vulnérabilité activement exploitée sans correctif —
 *   c'est-à-dire exactement la situation qui demande une décision humaine.
 * - **KEV s'évalue indépendamment de la sévérité.** Une « moyenne » exploitée dans la
 *   nature l'emporte sur une « critique » qui ne l'a jamais été.
 * - **Les constats de la revue IA sont exclus par défaut.** Ils viennent d'un modèle
 *   local à qui l'on a donné le code source du dépôt : un dépôt hostile peut les
 *   orienter, et une « critique » inventée ferait échouer la compilation de
 *   quelqu'un.
 * - **Les constats de qualité ne font jamais échouer une compilation**, et
 *   contrairement à la revue IA, sans option pour revenir dessus. Un backlog de
 *   qualité est volumineux par nature, et un gate qui rougit le jour où quelqu'un
 *   active un linter est un gate qu'on désactive. L'absence de drapeau est
 *   délibérée : une option ferait de « la qualité ne bloque jamais » une phrase à
 *   astérisque.
 */

/** Du pire au moins grave ; l'indice **est** le rang de comparaison. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as const;

export const DEFAULT_FAIL_ON_SEVERITY = 'high';

export const STATE_OPEN = 'open';
export const TRIAGE_UNDER_REVIEW = 'under_review';
export const TRIAGE_AFFECTED = 'affected';

export const AI_REVIEW_TYPE = 'ai_review';

/**
 * Les types qui décrivent *comment* le code est écrit plutôt que s'il est sûr.
 * Exclus de tout verdict, inconditionnellement.
 */
export const QUALITY_TYPES: readonly string[] = ['quality'];

/** Ce que l'appelant considère comme inacceptable. */
export interface GatePolicy {
    /** Échouer dès qu'un problème ouvert atteint cette sévérité. `null` désactive
     *  entièrement la règle de sévérité — utile pour ne barrer que sur KEV. */
    failOnSeverity: string | null;
    /** Échouer sur tout problème ouvert au catalogue CISA KEV, quelle que soit sa sévérité. */
    failOnKev: boolean;
    /** N'échouer que sur les problèmes ayant un correctif publié. */
    fixableOnly: boolean;
    /** Compter aussi les problèmes déjà tranchés par un triage. */
    includeTriaged: boolean;
    /** Laisser les constats de la revue IA peser sur le verdict. */
    includeAiReview: boolean;
}

export const BUILT_IN_POLICY: GatePolicy = Object.freeze({
    failOnSeverity: DEFAULT_FAIL_ON_SEVERITY,
    failOnKev: true,
    fixableOnly: false,
    includeTriaged: false,
    includeAiReview: false
});

/** Le sous-ensemble d'un problème que l'évaluation regarde — une dizaine de champs. */
export interface GateIssue {
    id: number;
    state: string | null;
    type: string | null;
    severity: string | null;
    identifier: string | null;
    packageName: string | null;
    fixVersions: string | null;
    isKev: boolean | null;
    triageStatus: string | null;
}

export interface Violation {
    rule: 'kev' | 'severity';
    issueId: number;
    identifier: string | null;
    severity: string;
    package: string | null;
    fixVersions: string | null;
    reason: string;
}

export interface GateVerdict {
    passed: boolean;
    violations: Violation[];
    evaluated: number;
    countsBySeverity: Record<string, number>;
}

/**
 * Position dans `SEVERITY_ORDER` ; une valeur inconnue se classe en dernier.
 *
 * `unknown` se classe volontairement **sous** `low` : le backend OSV le renvoie dès
 * qu'un avis n'a pas de sévérité normalisée, et le traiter en pire cas ferait échouer
 * toutes les compilations sur ce backend.
 */
export function severityRank(severity: string | null | undefined): number {
    const index = SEVERITY_ORDER.indexOf((severity || 'unknown').toLowerCase() as (typeof SEVERITY_ORDER)[number]);
    return index === -1 ? SEVERITY_ORDER.length : index;
}

export function isAtLeast(severity: string | null | undefined, threshold: string): boolean {
    return severityRank(severity) <= severityRank(threshold);
}

function isConsidered(issue: GateIssue, policy: GatePolicy): boolean {
    if (issue.state !== STATE_OPEN) return false;
    if (issue.type != null && QUALITY_TYPES.includes(issue.type)) return false;
    if (issue.type === AI_REVIEW_TYPE && !policy.includeAiReview) return false;
    if (!policy.includeTriaged && issue.triageStatus !== TRIAGE_UNDER_REVIEW && issue.triageStatus !== TRIAGE_AFFECTED) {
        return false;
    }
    // `not policy.fixable_only or issue.fix_versions` : une chaîne vide compte comme
    // absente, comme en Python.
    if (policy.fixableOnly && !issue.fixVersions) return false;
    return true;
}

function violation(issue: GateIssue, rule: 'kev' | 'severity', reason: string): Violation {
    return {
        rule,
        issueId: issue.id,
        identifier: issue.identifier,
        severity: (issue.severity || 'unknown').toLowerCase(),
        package: issue.packageName,
        fixVersions: issue.fixVersions,
        reason
    };
}

/** Applique `policy` aux problèmes d'une cible et explique le résultat. */
export function evaluate(issues: Iterable<GateIssue>, policy: GatePolicy): GateVerdict {
    const considered = [...issues].filter((issue) => isConsidered(issue, policy));

    const countsBySeverity: Record<string, number> = {};
    for (const issue of considered) {
        const key = (issue.severity || 'unknown').toLowerCase();
        countsBySeverity[key] = (countsBySeverity[key] ?? 0) + 1;
    }

    const violations: Violation[] = [];
    for (const issue of considered) {
        if (policy.failOnKev && issue.isKev) {
            violations.push(violation(issue, 'kev', 'vulnérabilité activement exploitée (catalogue CISA KEV)'));
            // Une violation par problème suffit à faire échouer la compilation.
            // Ne signaler que la règle KEV, et pas aussi la sévérité, garde la sortie
            // actionnable plutôt que dupliquée.
            continue;
        }
        if (policy.failOnSeverity && isAtLeast(issue.severity, policy.failOnSeverity)) {
            violations.push(violation(issue, 'severity', `sévérité ${issue.severity || 'unknown'} ≥ seuil ${policy.failOnSeverity}`));
        }
    }

    return {
        passed: violations.length === 0,
        violations,
        evaluated: considered.length,
        countsBySeverity
    };
}

/**
 * Une politique demandée par un appelant ne peut que **durcir** celle qui est stockée.
 *
 * C'est un contrôle de sécurité, pas une commodité : sans lui, n'importe quel pipeline
 * pourrait passer `failOnSeverity: null` dans le corps de sa requête et rendre vert
 * tout ce qu'il veut. Les tentatives d'assouplissement sont renvoyées à l'appelant
 * plutôt qu'ignorées en silence — un pipeline qui croit avoir désactivé une règle doit
 * l'apprendre.
 */
export function harden(base: GatePolicy, requested: RequestedPolicy): { policy: GatePolicy; ignoredRelaxations: string[] } {
    const policy: GatePolicy = { ...base };
    const ignoredRelaxations: string[] = [];

    if ('failOnSeverity' in requested) {
        const wanted = requested.failOnSeverity;
        if (wanted === null) {
            // Retirer explicitement la règle de sévérité est un assouplissement — sauf
            // s'il n'y avait pas de règle au départ.
            if (base.failOnSeverity !== null) ignoredRelaxations.push('fail_on_severity');
        } else if (wanted !== undefined) {
            if (base.failOnSeverity === null) {
                // Ajouter une règle là où il n'y en avait pas est un durcissement.
                policy.failOnSeverity = wanted.toLowerCase();
            } else {
                // `SEVERITY_ORDER` va du pire au moins grave, donc un rang *plus grand*
                // est un seuil *plus bas*, qui échoue sur davantage de problèmes —
                // c'est-à-dire plus strict. Inverser cette comparaison livrerait
                // l'exact contraire de la fonctionnalité : un pipeline libre de
                // remonter son seuil jusqu'à `critical`.
                const wantedRank = severityRank(wanted);
                const baseRank = severityRank(base.failOnSeverity);
                if (wantedRank > baseRank) policy.failOnSeverity = wanted.toLowerCase();
                else if (wantedRank < baseRank) ignoredRelaxations.push('fail_on_severity');
                // Rangs égaux : ni durcissement ni assouplissement, rien à signaler.
            }
        }
    }

    for (const [flag, strictValue] of STRICT_FLAG_VALUE) {
        if (!(flag in requested)) continue;
        const wanted = Boolean(requested[flag]);
        if (wanted === policy[flag]) continue;
        if (wanted === strictValue) policy[flag] = wanted;
        else ignoredRelaxations.push(SNAKE_CASE[flag]);
    }

    return { policy, ignoredRelaxations };
}

/**
 * Ce que l'appelant a réellement envoyé.
 *
 * La présence d'une clé compte, pas sa valeur : sans cette distinction, tout appelant
 * qui omet `failOnSeverity` semblerait demander le défaut du schéma et s'entendrait
 * répondre que sa requête a été refusée, à chaque appel. C'est l'équivalent du
 * `model_dump(exclude_unset=True)` de Pydantic.
 */
export type RequestedPolicy = Partial<GatePolicy>;

/**
 * Pour chaque drapeau, la valeur qui *durcit*. « Plus strict » ne veut pas dire
 * « vrai » : `fixableOnly` à vrai réduit l'ensemble évalué, donc c'est `false` qui
 * durcit.
 */
const STRICT_FLAG_VALUE: readonly [keyof GatePolicy & ('failOnKev' | 'includeTriaged' | 'includeAiReview' | 'fixableOnly'), boolean][] = [
    ['failOnKev', true],
    ['includeTriaged', true],
    ['includeAiReview', true],
    ['fixableOnly', false]
];

/** Les noms rendus à l'appelant restent ceux de l'API, en snake_case. */
const SNAKE_CASE: Record<string, string> = {
    failOnKev: 'fail_on_kev',
    includeTriaged: 'include_triaged',
    includeAiReview: 'include_ai_review',
    fixableOnly: 'fixable_only'
};
