/**
 * Pass/fail verdict of a target's backlog against a policy.
 *
 * This is what makes Zanshin usable from a pipeline rather than only from a browser: a
 * CI job asks "given what you know about this target, should this build fail?" and gets
 * back a reasoned verdict.
 *
 * Pure functions over a list of issues — no HTTP, no session — so that the semantics can
 * be tested exhaustively, and so that the same evaluation serves the `POST /api/v1/gate`
 * endpoint, the Security screen's badge and the notification threshold. Reimplementing
 * the rule in SQL for one of the three would make it diverge the first time a flag was
 * added.
 *
 * Decisions worth stating, carried over unchanged from the Python implementation:
 *
 * - **A triaged issue does not fail a build by default.** An argued `not_affected`
 *   judgement is the whole point of triage; a gate that ignores it sends teams back to
 *   disabling the gate. `includeTriaged` exists for the audit case where the raw picture
 *   is wanted.
 * - **"Fixable only" is offered, and is not the default.** Failing only on what has a
 *   published fix is the pragmatic setting, but as a default it would silently tolerate
 *   an actively exploited vulnerability with no fix — that is, exactly the situation that
 *   calls for a human decision.
 * - **KEV is evaluated independently of severity.** A "medium" exploited in the wild
 *   outranks a "critical" that never has been.
 * - **AI review findings are excluded by default.** They come from a local model that was
 *   handed the repository's source code: a hostile repository can steer them, and an
 *   invented "critical" would fail somebody's build.
 * - **Quality findings never fail a build**, and unlike AI review, with no option to go
 *   back on it. A quality backlog is voluminous by nature, and a gate that turns red the
 *   day someone switches on a linter is a gate that gets switched off. The absence of a
 *   flag is deliberate: an option would make "quality never blocks" a sentence with an
 *   asterisk.
 */

/** Worst to least severe; the index **is** the comparison rank. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'] as const;

export const DEFAULT_FAIL_ON_SEVERITY = 'high';

export const STATE_OPEN = 'open';
export const TRIAGE_UNDER_REVIEW = 'under_review';
export const TRIAGE_AFFECTED = 'affected';

export const AI_REVIEW_TYPE = 'ai_review';

/**
 * The types that describe *how* the code is written rather than whether it is safe.
 * Excluded from every verdict, unconditionally.
 */
export const QUALITY_TYPES: readonly string[] = ['quality'];

/** What the caller considers unacceptable. */
export interface GatePolicy {
    /** Fail as soon as an open issue reaches this severity. `null` disables the
     *  severity rule entirely — useful for blocking on KEV alone. */
    failOnSeverity: string | null;
    /** Fail on any open issue in the CISA KEV catalog, whatever its severity. */
    failOnKev: boolean;
    /** Fail only on issues that have a published fix. */
    fixableOnly: boolean;
    /** Also count issues already settled by a triage decision. */
    includeTriaged: boolean;
    /** Let AI review findings weigh on the verdict. */
    includeAiReview: boolean;
}

export const BUILT_IN_POLICY: GatePolicy = Object.freeze({
    failOnSeverity: DEFAULT_FAIL_ON_SEVERITY,
    failOnKev: true,
    fixableOnly: false,
    includeTriaged: false,
    includeAiReview: false
});

/** The subset of an issue the evaluation looks at — about ten fields. */
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
 * Position in `SEVERITY_ORDER`; an unknown value ranks last.
 *
 * `unknown` deliberately ranks **below** `low`: the OSV back end returns it whenever an
 * advisory has no normalized severity, and treating it as the worst case would fail every
 * build on that back end.
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
    // `not policy.fixable_only or issue.fix_versions`: an empty string counts as
    // absent, as in Python.
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

/** Applies `policy` to a target's issues and explains the result. */
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
            violations.push(violation(issue, 'kev', 'actively exploited vulnerability (CISA KEV catalog)'));
            // One violation per issue is enough to fail the build. Reporting only the
            // KEV rule, and not the severity one as well, keeps the output actionable
            // rather than duplicated.
            continue;
        }
        if (policy.failOnSeverity && isAtLeast(issue.severity, policy.failOnSeverity)) {
            violations.push(violation(issue, 'severity', `severity ${issue.severity || 'unknown'} >= threshold ${policy.failOnSeverity}`));
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
 * A policy requested by a caller can only **tighten** the stored one.
 *
 * This is a security control, not a convenience: without it, any pipeline could pass
 * `failOnSeverity: null` in its request body and turn anything it likes green. Attempted
 * relaxations are reported back to the caller rather than ignored silently — a pipeline
 * that believes it has disabled a rule needs to find out.
 */
export function harden(base: GatePolicy, requested: RequestedPolicy): { policy: GatePolicy; ignoredRelaxations: string[] } {
    const policy: GatePolicy = { ...base };
    const ignoredRelaxations: string[] = [];

    if ('failOnSeverity' in requested) {
        const wanted = requested.failOnSeverity;
        if (wanted === null) {
            // Explicitly removing the severity rule is a relaxation — unless there was
            // no rule to begin with.
            if (base.failOnSeverity !== null) ignoredRelaxations.push('fail_on_severity');
        } else if (wanted !== undefined) {
            if (base.failOnSeverity === null) {
                // Adding a rule where there was none is a tightening.
                policy.failOnSeverity = wanted.toLowerCase();
            } else {
                // `SEVERITY_ORDER` runs worst to least severe, so a *larger* rank is a
                // *lower* threshold, which fails on more issues — that is, stricter.
                // Inverting this comparison would deliver the exact opposite of the
                // feature: a pipeline free to raise its threshold up to `critical`.
                const wantedRank = severityRank(wanted);
                const baseRank = severityRank(base.failOnSeverity);
                if (wantedRank > baseRank) policy.failOnSeverity = wanted.toLowerCase();
                else if (wantedRank < baseRank) ignoredRelaxations.push('fail_on_severity');
                // Equal ranks: neither tightening nor relaxation, nothing to report.
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
 * What the caller actually sent.
 *
 * The presence of a key matters, not its value: without that distinction, any caller
 * omitting `failOnSeverity` would appear to be asking for the schema default and would be
 * told its request was refused, on every call. This is the equivalent of Pydantic's
 * `model_dump(exclude_unset=True)`.
 */
export type RequestedPolicy = Partial<GatePolicy>;

/**
 * For each flag, the value that *tightens*. "Stricter" does not mean "true":
 * `fixableOnly` set to true shrinks the evaluated set, so `false` is what tightens.
 */
const STRICT_FLAG_VALUE: readonly [keyof GatePolicy & ('failOnKev' | 'includeTriaged' | 'includeAiReview' | 'fixableOnly'), boolean][] = [
    ['failOnKev', true],
    ['includeTriaged', true],
    ['includeAiReview', true],
    ['fixableOnly', false]
];

/** The names returned to the caller stay the API's, in snake_case. */
const SNAKE_CASE: Record<string, string> = {
    failOnKev: 'fail_on_kev',
    includeTriaged: 'include_triaged',
    includeAiReview: 'include_ai_review',
    fixableOnly: 'fixable_only'
};
