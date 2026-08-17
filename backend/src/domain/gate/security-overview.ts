import { GateIssue, GateVerdict, evaluate } from './policy-gate';
import { PolicyLookup, ResolvedPolicy, StoredPolicy, resolvePolicy } from './policy-resolution';

/**
 * Where each target stands, in one picture.
 *
 * **The gate verdict was always computed and never shown.** It served
 * `POST /api/v1/gate`, and a team could only learn whether its repository passed by
 * running a build against it — the application knew the answer and kept it to itself.
 *
 * ## Two rules shape this implementation
 *
 * **The verdict here must be the one the API returns.** This module therefore computes no
 * pass/fail of its own: it calls `evaluate` with the same policy resolution as the
 * endpoint, over the same issues. A SQL aggregate recounting "open issues above the
 * threshold" would agree today and diverge the first time a flag was added to
 * `GatePolicy` — and nobody would see it until a pipeline and a screen contradicted each
 * other about the same repository.
 *
 * **A screen listing N targets must not cost N queries.** Both traps are real: resolving
 * a policy per target costs one or two queries each, loading a target's issues costs
 * another. Everything is therefore read once and matched up in memory here — hence a pure
 * function over already-loaded data, rather than a service holding a session.
 *
 * **A target never scanned, or whose last scan failed, is not a target that passes.** It
 * is a target nobody has looked at — the worst posture there is, and the one no screen
 * named. An empty backlog passes every policy: saying so without that qualifier would be
 * the most misleading thing this screen could do.
 */

export const TARGET_REPOSITORY = 'repository';
export const TARGET_CONTAINER = 'container';

/** What the last scan says about how much the verdict can be trusted. */
export const OBSERVATION_OK = 'ok';
export const OBSERVATION_NEVER_SCANNED = 'never_scanned';
export const OBSERVATION_LAST_SCAN_FAILED = 'last_scan_failed';
export const OBSERVATION_IN_PROGRESS = 'in_progress';

export type Observation = typeof OBSERVATION_OK | typeof OBSERVATION_NEVER_SCANNED | typeof OBSERVATION_LAST_SCAN_FAILED | typeof OBSERVATION_IN_PROGRESS;

const IN_FLIGHT_STATUSES = ['pending', 'scanning'];

export interface OverviewTarget {
    id: number;
    /** The readable name; for a repository, its name or failing that its URL. */
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
     * Does the verdict rest on a real observation?
     *
     * A target nobody has successfully scanned produces an empty backlog, and an empty
     * backlog passes every policy.
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
    /** Every active policy, read in one go. */
    policies: { targetKind: string; targetId: number; policy: StoredPolicy }[];
    /** Every open issue, read in one go. */
    openIssues: (GateIssue & { repoId: number | null; containerId: number | null })[];
    latestScanByRepository: Map<number, LatestScan>;
    latestScanByContainer: Map<number, LatestScan>;
}

/** Assembles the view from already-read data. No queries here, by construction. */
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
        // Counted over the evaluated issues, not over the whole backlog: a KEV discarded
        // by a triage or by `fixableOnly` does not weigh on the verdict, and showing it in
        // the same banner would present a number that corresponds to nothing.
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
    // The same precedence as `resolvePolicy`, applied to policies read only once: calling
    // it per target is exactly what would make this screen 2N queries.
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

/** The global policy is stored with the `global` scope and identifier 0. */
const GLOBAL_KEY = 'global:0';

function scopeKey(kind: string, id: number): string {
    return `${kind}:${id}`;
}
