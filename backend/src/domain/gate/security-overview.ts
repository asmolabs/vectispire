import { GateIssue, GateVerdict, evaluate } from './policy-gate';
import { PolicyLookup, ResolvedPolicy, StoredPolicy, resolvePolicy } from './policy-resolution';

/**
 * Où en est chaque cible, en une image.
 *
 * **Le verdict du gate a toujours été calculé et jamais montré.** Il servait
 * `POST /api/v1/gate`, et une équipe ne pouvait apprendre si son dépôt passait qu'en
 * lançant une compilation contre lui — l'application connaissait la réponse et la
 * gardait pour elle.
 *
 * ## Deux règles façonnent cette implémentation
 *
 * **Le verdict d'ici doit être celui que rend l'API.** Ce module ne calcule donc pas de
 * passé/échoué : il appelle `evaluate` avec la même résolution de politique que
 * l'endpoint, sur les mêmes problèmes. Une agrégation SQL qui recompterait « les
 * problèmes ouverts au-dessus du seuil » serait d'accord aujourd'hui et divergerait au
 * premier drapeau ajouté à `GatePolicy` — et personne ne le verrait avant qu'un pipeline
 * et un écran ne se contredisent sur le même dépôt.
 *
 * **Un écran listant N cibles ne doit pas coûter N requêtes.** Les deux pièges sont
 * réels : résoudre une politique par cible coûte une ou deux requêtes chacune, charger
 * les problèmes d'une cible en coûte une autre. Tout est donc lu une fois et apparié en
 * mémoire ici — d'où une fonction pure sur des données déjà chargées, plutôt qu'un
 * service tenant une session.
 *
 * **Une cible jamais scannée, ou dont le dernier scan a échoué, n'est pas une cible qui
 * passe.** C'est une cible que personne n'a regardée — la pire posture qui soit, et
 * celle qu'aucun écran ne nommait. Un backlog vide passe toutes les politiques : le dire
 * sans ce qualificatif serait la chose la plus trompeuse que cet écran puisse faire.
 */

export const TARGET_REPOSITORY = 'repository';
export const TARGET_CONTAINER = 'container';

/** Ce que le dernier scan dit de la confiance qu'on peut accorder au verdict. */
export const OBSERVATION_OK = 'ok';
export const OBSERVATION_NEVER_SCANNED = 'never_scanned';
export const OBSERVATION_LAST_SCAN_FAILED = 'last_scan_failed';
export const OBSERVATION_IN_PROGRESS = 'in_progress';

export type Observation = typeof OBSERVATION_OK | typeof OBSERVATION_NEVER_SCANNED | typeof OBSERVATION_LAST_SCAN_FAILED | typeof OBSERVATION_IN_PROGRESS;

const IN_FLIGHT_STATUSES = ['pending', 'scanning'];

export interface OverviewTarget {
    id: number;
    /** Le nom lisible ; pour un dépôt, son nom ou à défaut son URL. */
    name: string;
}

export interface LatestScan {
    id: number;
    status: string | null;
    createdAt: Date | null;
}

export interface TargetPosture {
    kind: typeof TARGET_REPOSITORY | typeof TARGET_CONTAINER;
    targetId: number;
    name: string;
    verdict: GateVerdict;
    policy: ResolvedPolicy;
    observation: Observation;
    lastScanAt: Date | null;
    lastScanId: number | null;
    passed: boolean;
    /**
     * Le verdict repose-t-il sur une observation réelle ?
     *
     * Une cible que personne n'a scannée avec succès produit un backlog vide, et un
     * backlog vide passe toutes les politiques.
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

export interface OverviewInput {
    repositories: OverviewTarget[];
    containers: OverviewTarget[];
    /** Toutes les politiques actives, lues en une fois. */
    policies: { targetKind: string; targetId: number; policy: StoredPolicy }[];
    /** Tous les problèmes ouverts, lus en une fois. */
    openIssues: (GateIssue & { repoId: number | null; containerId: number | null })[];
    latestScanByRepository: Map<number, LatestScan>;
    latestScanByContainer: Map<number, LatestScan>;
}

/** Assemble la vue à partir de données déjà lues. Aucune requête ici, par construction. */
export function buildOverview(input: OverviewInput): SecurityOverview {
    const byScope = new Map<string, StoredPolicy>();
    for (const entry of input.policies) byScope.set(scopeKey(entry.targetKind, entry.targetId), entry.policy);

    const issuesByTarget = new Map<string, GateIssue[]>();
    for (const issue of input.openIssues) {
        const key = issue.repoId != null ? scopeKey(TARGET_REPOSITORY, issue.repoId) : scopeKey(TARGET_CONTAINER, issue.containerId ?? -1);
        const bucket = issuesByTarget.get(key);
        if (bucket) bucket.push(issue);
        else issuesByTarget.set(key, [issue]);
    }

    const targets: TargetPosture[] = [
        ...input.repositories.map((repository) => posture(TARGET_REPOSITORY, repository, byScope, issuesByTarget, input.latestScanByRepository.get(repository.id))),
        ...input.containers.map((container) => posture(TARGET_CONTAINER, container, byScope, issuesByTarget, input.latestScanByContainer.get(container.id)))
    ];

    return {
        targets,
        failingCount: targets.filter((target) => !target.passed).length,
        totalCount: targets.length,
        // Compté sur les problèmes évalués, et non sur tout le backlog : un KEV écarté
        // par un triage ou par `fixableOnly` ne pèse pas sur le verdict, et l'afficher
        // dans le même bandeau ferait lire un chiffre qui ne correspond à rien.
        kevCount: targets.reduce((total, target) => total + target.verdict.violations.filter((violation) => violation.rule === 'kev').length, 0),
        neverScannedCount: targets.filter((target) => target.observation === OBSERVATION_NEVER_SCANNED).length,
        lastScanFailedCount: targets.filter((target) => target.observation === OBSERVATION_LAST_SCAN_FAILED).length
    };
}

function posture(
    kind: typeof TARGET_REPOSITORY | typeof TARGET_CONTAINER,
    target: OverviewTarget,
    byScope: Map<string, StoredPolicy>,
    issuesByTarget: Map<string, GateIssue[]>,
    latestScan: LatestScan | undefined
): TargetPosture {
    // La même précédence que `resolvePolicy`, appliquée sur des politiques lues une
    // seule fois : l'appeler par cible est exactement ce qui ferait de cet écran 2N
    // requêtes.
    const lookup: PolicyLookup = {
        forTarget: byScope.get(scopeKey(kind, target.id)) ?? null,
        global: byScope.get(GLOBAL_KEY) ?? null
    };
    const policy = resolvePolicy(lookup);
    const observation = observationOf(latestScan);

    const verdict = evaluate(issuesByTarget.get(scopeKey(kind, target.id)) ?? [], policy.policy);

    return {
        kind,
        targetId: target.id,
        name: target.name,
        verdict,
        policy,
        observation,
        lastScanAt: latestScan?.createdAt ?? null,
        lastScanId: latestScan?.id ?? null,
        passed: verdict.passed,
        observed: observation === OBSERVATION_OK
    };
}

function observationOf(latestScan: LatestScan | undefined): Observation {
    if (!latestScan) return OBSERVATION_NEVER_SCANNED;
    if (latestScan.status && IN_FLIGHT_STATUSES.includes(latestScan.status)) return OBSERVATION_IN_PROGRESS;
    if (latestScan.status === 'failed') return OBSERVATION_LAST_SCAN_FAILED;
    return OBSERVATION_OK;
}

/** La politique globale est stockée avec la portée `global` et l'identifiant 0. */
const GLOBAL_KEY = 'global:0';

function scopeKey(kind: string, id: number): string {
    return `${kind}:${id}`;
}
