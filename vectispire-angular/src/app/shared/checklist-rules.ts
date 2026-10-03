import type {
    ChecklistAllowedComponent,
    ChecklistCoverageScope,
    ChecklistRule,
    ChecklistRuleKind,
    ChecklistSeverity,
    ChecklistThreshold
} from '../core/api.models';
import { I18nService } from '../core/i18n/i18n.service';
import { findingTypeLabel } from './finding-types';

/**
 * The rules a checklist line is measured by (decision 0032 §6), **written once for both screens**: the
 * template screen binds them, the project checklist shows them beside each measurement, and a rule
 * worded one way on one and another way on the other would be two rules to the reader.
 *
 * **The bounds are the server's**, copied from `ChecklistRule`, `SeverityThreshold`, `AllowedComponent`,
 * `ToolScope` and `PluginManifest.requireId` so that the form refuses what the route would, in the
 * reader's language rather than in the server's English. The server has the last word, and says it.
 *
 * **No parameter is assumed.** A threshold is the organisation's KPI, stated beside the KPI's text, and
 * never read out of it (§3, step 4); the form proposes seven days for the maximum age, as the decision
 * says it does, and proposes nothing else: whether the schedule must match, the coverage metric and how
 * it is aggregated are chosen, or the rule is not sent.
 */

/** In the order the form offers them: from the scan's own dependency step to the organisation's own list. */
export const RULE_KINDS: readonly ChecklistRuleKind[] = [
    'dependency_analysis',
    'findings_threshold',
    'coverage_threshold',
    'test_suite_passed',
    'component_versions',
    'component_present'
];

// Literal keys, so that a new value cannot ship as a raw key (decision 0019). The i18n check counts
// none of these — they are not `t('…')` calls — so the specs read each against both bundles.
export const RULE_KIND_KEYS = {
    dependency_analysis: 'checklist_rules.kind_dependency_analysis',
    findings_threshold: 'checklist_rules.kind_findings_threshold',
    coverage_threshold: 'checklist_rules.kind_coverage_threshold',
    test_suite_passed: 'checklist_rules.kind_test_suite_passed',
    component_versions: 'checklist_rules.kind_component_versions',
    component_present: 'checklist_rules.kind_component_present'
} as const satisfies Record<ChecklistRuleKind, string>;

export const SEVERITIES: readonly ChecklistSeverity[] = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];

export const SEVERITY_KEYS = {
    critical: 'severities.critical',
    high: 'severities.high',
    medium: 'severities.medium',
    low: 'severities.low',
    negligible: 'severities.negligible',
    unknown: 'severities.unknown'
} as const satisfies Record<ChecklistSeverity, string>;

export type CoverageMetric = NonNullable<ChecklistRule['metric']>;
export type CoverageAggregation = NonNullable<ChecklistRule['aggregation']>;

export const METRICS: readonly CoverageMetric[] = ['line', 'branch'];
export const AGGREGATIONS: readonly CoverageAggregation[] = ['per_repository', 'project_weighted'];

export const METRIC_KEYS = {
    line: 'checklist_rules.metric_line',
    branch: 'checklist_rules.metric_branch'
} as const satisfies Record<CoverageMetric, string>;

export const AGGREGATION_KEYS = {
    per_repository: 'checklist_rules.aggregation_per_repository',
    project_weighted: 'checklist_rules.aggregation_project_weighted'
} as const satisfies Record<CoverageAggregation, string>;

/**
 * The built-in steps a scan records as examined — `ToolScope.BUILT_IN_TYPES`, in the order the backlog
 * offers their types. A scope on another type is refused: nothing records whether it looked.
 */
export const BUILT_IN_SCOPES = [
    'builtin:vulnerability',
    'builtin:secret',
    'builtin:iac',
    'builtin:sast',
    'builtin:quality',
    'builtin:eol',
    'builtin:license'
] as const;

/** The server's bounds, each named where the server holds it. */
export const RULE_BOUNDS = {
    /** `ChecklistRule.MAX_AGE_DAYS`: a year and a day. */
    minAgeDays: 1,
    maxAgeDays: 366,
    /** `ChecklistRule.MAX_SCOPES`, `MAX_COMPONENTS`, `MAX_PATTERN`, `MAX_TESTS`. */
    maxScopes: 20,
    maxComponents: 50,
    maxPattern: 500,
    maxTests: 10_000_000,
    /** `SeverityThreshold.MAX_OPEN`. */
    maxOpen: 1_000_000,
    /** `AllowedComponent.MAX_PREFIX`, `MAX_VERSIONS`, `MAX_VERSION`. */
    maxPrefix: 500,
    maxVersions: 100,
    maxVersion: 255,
    /** `Ratios.SCALE`: four decimals keep the canonical form out of scientific notation. */
    ratioDecimals: 4,
    /** `CoverageScope.MAX_PATTERNS`, in each of include and exclude; a pattern is `MAX_PATTERN` long at most. */
    maxCoveragePatterns: 20
} as const;

/** What the form proposes for a new rule's maximum age, as decision 0032 §6 says it does — and nothing else. */
export const PROPOSED_MAX_AGE_DAYS = 7;

/** `PluginManifest.requireId`: 2 to 40, lowercase letters and digits, inner hyphens. */
const PLUGIN_SCOPE = /^plugin:[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$/;
/** `ToolScope.parse` for an import: a declared source's slug (2 to 40), a slash, the tool's name. */
const IMPORT_SCOPE = /^import:[a-z0-9][a-z0-9-]{0,38}[a-z0-9]\/(.+)$/;
// eslint-disable-next-line no-control-regex -- the server refuses control characters; so does the form.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** One severity's threshold as the form edits it: either, both, or neither — neither states nothing. */
export interface ThresholdDraft {
    maxOpen: number | null;
    minResolvedRatio: number | null;
}

/**
 * One declared package as the form edits it: its allowed versions typed as a list, separated by commas —
 * a comma inside a Maven range's brackets is the range's own. Unused by a presence rule.
 */
export interface ComponentDraft {
    purlPrefix: string;
    versions: string;
}

/** A rule as the form edits it, every kind's fields at once; `kind` null is "measured by no rule". */
export interface RuleDraft {
    kind: ChecklistRuleKind | null;
    maxAgeDays: number | null;
    /** Stated, never assumed: null until the person chooses. */
    requireSchedule: boolean | null;
    scopes: string[];
    thresholds: Record<ChecklistSeverity, ThresholdDraft>;
    metric: CoverageMetric | null;
    minimumRatio: number | null;
    aggregation: CoverageAggregation | null;
    suitePattern: string;
    minimumTests: number | null;
    components: ComponentDraft[];
    /** A coverage rule's packages, typed as lists separated by commas; both blank is the whole report. */
    scopeInclude: string;
    scopeExclude: string;
}

/** Why the form refuses a rule, in the order a person reads the form. */
export type RuleProblem =
    | 'max_age'
    | 'require_schedule'
    | 'scopes_count'
    | 'scope_invalid'
    | 'scope_twice'
    | 'threshold_needed'
    | 'max_open'
    | 'resolved_ratio'
    | 'metric'
    | 'minimum_ratio'
    | 'aggregation'
    | 'coverage_patterns_count'
    | 'coverage_pattern'
    | 'coverage_pattern_twice'
    | 'pattern'
    | 'minimum_tests'
    | 'components_count'
    | 'purl'
    | 'purl_twice'
    | 'versions'
    | 'version_length'
    | 'version_range';

export const RULE_PROBLEM_KEYS = {
    max_age: 'checklist_rules.problem_max_age',
    require_schedule: 'checklist_rules.problem_require_schedule',
    scopes_count: 'checklist_rules.problem_scopes_count',
    scope_invalid: 'checklist_rules.problem_scope_invalid',
    scope_twice: 'checklist_rules.problem_scope_twice',
    threshold_needed: 'checklist_rules.problem_threshold_needed',
    max_open: 'checklist_rules.problem_max_open',
    resolved_ratio: 'checklist_rules.problem_resolved_ratio',
    metric: 'checklist_rules.problem_metric',
    minimum_ratio: 'checklist_rules.problem_minimum_ratio',
    aggregation: 'checklist_rules.problem_aggregation',
    coverage_patterns_count: 'checklist_rules.problem_coverage_patterns_count',
    coverage_pattern: 'checklist_rules.problem_coverage_pattern',
    coverage_pattern_twice: 'checklist_rules.problem_coverage_pattern_twice',
    pattern: 'checklist_rules.problem_pattern',
    minimum_tests: 'checklist_rules.problem_minimum_tests',
    components_count: 'checklist_rules.problem_components_count',
    purl: 'checklist_rules.problem_purl',
    purl_twice: 'checklist_rules.problem_purl_twice',
    versions: 'checklist_rules.problem_versions',
    version_length: 'checklist_rules.problem_version_length',
    version_range: 'checklist_rules.problem_version_range'
} as const satisfies Record<RuleProblem, string>;

/** A refusal and what its sentence names. */
export interface RuleRefusal {
    problem: RuleProblem;
    params: Record<string, string | number>;
}

// ---------------------------------------------------------------------- the form's model

function noThresholds(): Record<ChecklistSeverity, ThresholdDraft> {
    return Object.fromEntries(
        SEVERITIES.map((severity) => [severity, { maxOpen: null, minResolvedRatio: null }])
    ) as Record<ChecklistSeverity, ThresholdDraft>;
}

/** A new rule of a kind: seven days proposed, nothing else. */
export function emptyDraft(kind: ChecklistRuleKind | null): RuleDraft {
    return {
        kind,
        maxAgeDays: kind ? PROPOSED_MAX_AGE_DAYS : null,
        requireSchedule: null,
        scopes: [],
        thresholds: noThresholds(),
        metric: null,
        minimumRatio: null,
        aggregation: null,
        suitePattern: '',
        minimumTests: null,
        components: [],
        scopeInclude: '',
        scopeExclude: ''
    };
}

/**
 * The preset decision 0032 §6 names: "no plaintext secret in configuration" is the secret step's
 * findings with the critical and high counts at zero, over evidence at most a week old.
 */
export function secretsAtZero(): RuleDraft {
    const draft = emptyDraft('findings_threshold');
    draft.scopes = ['builtin:secret'];
    draft.thresholds.critical = { maxOpen: 0, minResolvedRatio: null };
    draft.thresholds.high = { maxOpen: 0, minResolvedRatio: null };
    draft.maxAgeDays = 7;
    return draft;
}

/** The form's state for a rule shown, or an empty one for a line measured by none. */
export function draftOf(rule: ChecklistRule | null): RuleDraft {
    const draft = emptyDraft(rule?.kind ?? null);
    if (!rule) return draft;
    draft.maxAgeDays = rule.maxAgeDays;
    draft.requireSchedule = rule.requireSchedule ?? null;
    draft.scopes = [...(rule.scopes ?? [])];
    for (const severity of SEVERITIES) {
        const threshold = rule.thresholds?.[severity];
        if (threshold) {
            draft.thresholds[severity] = {
                maxOpen: threshold.maxOpen ?? null,
                minResolvedRatio: threshold.minResolvedRatio ?? null
            };
        }
    }
    draft.metric = rule.metric ?? null;
    draft.minimumRatio = rule.minimumRatio ?? null;
    draft.aggregation = rule.aggregation ?? null;
    draft.suitePattern = rule.suitePattern ?? '';
    draft.minimumTests = rule.minimumTests ?? null;
    draft.components = (rule.components ?? []).map((component) => ({
        purlPrefix: component.purlPrefix,
        versions: (component.versions ?? []).join(', ')
    }));
    draft.scopeInclude = (rule.scope?.include ?? []).join(', ');
    draft.scopeExclude = (rule.scope?.exclude ?? []).join(', ');
    return draft;
}

/** The patterns typed in one of a coverage scope's lists, blanks dropped. */
export function patternsOf(typed: string): string[] {
    return typed
        .split(',')
        .map((pattern) => pattern.trim())
        .filter((pattern) => pattern.length > 0);
}

/**
 * Whether the server's `CoverageScope.check` takes a pattern over package paths: `**` a whole segment,
 * `*` within one, nothing else a wildcard; no leading, trailing or doubled slash, no backslash, no `.` or
 * `..` segment, and not a dotted package name — `org/example/service`, never `org.example.service`.
 */
export function coveragePatternAllowed(pattern: string): boolean {
    if (!pattern || pattern.length > RULE_BOUNDS.maxPattern || CONTROL.test(pattern)) return false;
    if (/[\\?[\]{}!]/.test(pattern)) return false;
    if (pattern.startsWith('/') || pattern.endsWith('/') || pattern.includes('//')) return false;
    if (!pattern.includes('/') && pattern.includes('.')) return false;
    return pattern
        .split('/')
        .every((segment) => segment !== '.' && segment !== '..' && (!segment.includes('**') || segment === '**'));
}

function coverageScopeRefusal(draft: RuleDraft): RuleRefusal | null {
    for (const typed of [draft.scopeInclude, draft.scopeExclude]) {
        const patterns = patternsOf(typed);
        if (patterns.length > RULE_BOUNDS.maxCoveragePatterns) {
            return { problem: 'coverage_patterns_count', params: { max: RULE_BOUNDS.maxCoveragePatterns } };
        }
        const seen = new Set<string>();
        for (const pattern of patterns) {
            if (!coveragePatternAllowed(pattern)) return { problem: 'coverage_pattern', params: { pattern } };
            if (seen.has(pattern)) return { problem: 'coverage_pattern_twice', params: { pattern } };
            seen.add(pattern);
        }
    }
    return null;
}

/** The scope a draft states, or none when both lists are blank — the whole report, as before scopes. */
function coverageScopeOf(draft: RuleDraft): ChecklistCoverageScope | null {
    const include = patternsOf(draft.scopeInclude);
    const exclude = patternsOf(draft.scopeExclude);
    if (include.length === 0 && exclude.length === 0) return null;
    const scope: ChecklistCoverageScope = {};
    if (include.length > 0) scope.include = include;
    if (exclude.length > 0) scope.exclude = exclude;
    return scope;
}

/** A scope as the server keys it: an imported tool's name lowercased and trimmed, like `ToolKeys.imported`. */
export function normalizedScope(scope: string): string {
    const trimmed = scope.trim();
    const match = /^(import:[^/]*\/)(.*)$/.exec(trimmed);
    return match ? match[1] + match[2].trim().toLowerCase() : trimmed;
}

/** Whether the server's `ToolScope.parse` takes the scope. */
export function scopeAllowed(scope: string): boolean {
    if ((BUILT_IN_SCOPES as readonly string[]).includes(scope)) return true;
    if (PLUGIN_SCOPE.test(scope)) return true;
    const imported = IMPORT_SCOPE.exec(scope);
    if (!imported) return false;
    const tool = imported[1].trim();
    return tool.length > 0 && tool.length <= 100 && !tool.includes(',') && !CONTROL.test(tool);
}

/** Whether a ratio is one the server writes: in [0, 1] (above 0 unless zero is allowed), four decimals at most. */
export function ratioAllowed(ratio: number | null, zeroAllowed: boolean): boolean {
    if (ratio === null || !Number.isFinite(ratio) || ratio < 0 || ratio > 1) return false;
    if (!zeroAllowed && ratio === 0) return false;
    const scaled = ratio * 10 ** RULE_BOUNDS.ratioDecimals;
    return Math.abs(Math.round(scaled) - scaled) < 1e-6;
}

function wholeIn(value: number | null, min: number, max: number): boolean {
    return value !== null && Number.isInteger(value) && value >= min && value <= max;
}

/**
 * The versions typed, split on the commas between them and never on one inside a range: `[1.17,2.0)` is
 * one entry, and `[1.0,1.2],[1.5,)` two — a union either way, since a version allowed by any entry is.
 */
export function versionsOf(component: ComponentDraft): string[] {
    const versions: string[] = [];
    let depth = 0;
    let current = '';
    for (const character of component.versions) {
        if (character === '[' || character === '(') depth++;
        if (character === ']' || character === ')') depth = Math.max(0, depth - 1);
        if (character === ',' && depth === 0) {
            versions.push(current);
            current = '';
        } else {
            current += character;
        }
    }
    versions.push(current);
    return versions.map((version) => version.trim()).filter((version) => version.length > 0);
}

/** `ChecklistRule`'s prefix check, shared by both component kinds; the refusal or null. */
function prefixesRefusal(draft: RuleDraft): RuleRefusal | null {
    if (draft.components.length === 0 || draft.components.length > RULE_BOUNDS.maxComponents) {
        return { problem: 'components_count', params: { max: RULE_BOUNDS.maxComponents } };
    }
    const prefixes = new Set<string>();
    for (const component of draft.components) {
        const prefix = component.purlPrefix.trim();
        if (
            !prefix.startsWith('pkg:') ||
            prefix.length <= 4 ||
            prefix.length > RULE_BOUNDS.maxPrefix ||
            /\s/.test(prefix) ||
            CONTROL.test(prefix) ||
            prefix.includes('@')
        ) {
            return { problem: 'purl', params: { prefix, max: RULE_BOUNDS.maxPrefix } };
        }
        if (prefixes.has(prefix)) return { problem: 'purl_twice', params: { prefix } };
        prefixes.add(prefix);
    }
    return null;
}

/** The thresholds a severity states; a severity left blank states none. */
function statedThresholds(draft: RuleDraft): [ChecklistSeverity, ThresholdDraft][] {
    return SEVERITIES.map(
        (severity) => [severity, draft.thresholds[severity]] as [ChecklistSeverity, ThresholdDraft]
    ).filter(([, threshold]) => threshold.maxOpen !== null || threshold.minResolvedRatio !== null);
}

function thresholdRefusal(draft: RuleDraft): RuleRefusal | null {
    for (const [severity, threshold] of statedThresholds(draft)) {
        if (threshold.maxOpen !== null && !wholeIn(threshold.maxOpen, 0, RULE_BOUNDS.maxOpen)) {
            return { problem: 'max_open', params: { severity, max: RULE_BOUNDS.maxOpen } };
        }
        if (threshold.minResolvedRatio !== null && !ratioAllowed(threshold.minResolvedRatio, true)) {
            return { problem: 'resolved_ratio', params: { severity } };
        }
    }
    return null;
}

/**
 * What the form refuses before sending, as the server would — the first refusal, in the order the form
 * reads; `null` when the server is the one left to judge, and for "no rule", which is always allowed.
 */
export function ruleRefusal(draft: RuleDraft): RuleRefusal | null {
    if (!draft.kind) return null;
    if (!wholeIn(draft.maxAgeDays, RULE_BOUNDS.minAgeDays, RULE_BOUNDS.maxAgeDays)) {
        return { problem: 'max_age', params: { min: RULE_BOUNDS.minAgeDays, max: RULE_BOUNDS.maxAgeDays } };
    }
    switch (draft.kind) {
        case 'dependency_analysis':
            if (draft.requireSchedule === null) return { problem: 'require_schedule', params: {} };
            return thresholdRefusal(draft);
        case 'findings_threshold': {
            if (draft.scopes.length === 0 || draft.scopes.length > RULE_BOUNDS.maxScopes) {
                return { problem: 'scopes_count', params: { max: RULE_BOUNDS.maxScopes } };
            }
            const seen = new Set<string>();
            for (const scope of draft.scopes.map(normalizedScope)) {
                if (!scopeAllowed(scope)) return { problem: 'scope_invalid', params: { scope } };
                if (seen.has(scope)) return { problem: 'scope_twice', params: { scope } };
                seen.add(scope);
            }
            if (statedThresholds(draft).length === 0) return { problem: 'threshold_needed', params: {} };
            return thresholdRefusal(draft);
        }
        case 'coverage_threshold':
            if (!draft.metric) return { problem: 'metric', params: {} };
            if (!ratioAllowed(draft.minimumRatio, false)) return { problem: 'minimum_ratio', params: {} };
            if (!draft.aggregation) return { problem: 'aggregation', params: {} };
            return coverageScopeRefusal(draft);
        case 'test_suite_passed': {
            const pattern = draft.suitePattern.trim();
            if (!pattern || pattern.length > RULE_BOUNDS.maxPattern || CONTROL.test(pattern)) {
                return { problem: 'pattern', params: { max: RULE_BOUNDS.maxPattern } };
            }
            if (!wholeIn(draft.minimumTests, 1, RULE_BOUNDS.maxTests)) {
                return { problem: 'minimum_tests', params: { max: RULE_BOUNDS.maxTests } };
            }
            return null;
        }
        case 'component_present':
            return prefixesRefusal(draft);
        case 'component_versions': {
            const prefixRefusal = prefixesRefusal(draft);
            if (prefixRefusal) return prefixRefusal;
            for (const component of draft.components) {
                const prefix = component.purlPrefix.trim();
                const versions = versionsOf(component);
                if (versions.length === 0 || versions.length > RULE_BOUNDS.maxVersions) {
                    return { problem: 'versions', params: { prefix, max: RULE_BOUNDS.maxVersions } };
                }
                if (versions.some((version) => version.length > RULE_BOUNDS.maxVersion || CONTROL.test(version))) {
                    return { problem: 'version_length', params: { prefix, max: RULE_BOUNDS.maxVersion } };
                }
                // `AllowedComponent.declared`: Maven's order is the only one implemented; the server reads the
                // range itself and says what is wrong with one that does not read.
                if (!prefix.startsWith('pkg:maven/') && versions.some((version) => /^[[(]/.test(version))) {
                    return { problem: 'version_range', params: { prefix } };
                }
            }
            return null;
        }
    }
}

function thresholdsOf(draft: RuleDraft): Partial<Record<ChecklistSeverity, ChecklistThreshold>> {
    const thresholds: Partial<Record<ChecklistSeverity, ChecklistThreshold>> = {};
    for (const [severity, threshold] of statedThresholds(draft)) {
        // Each key only when stated: a null maxOpen is not "no limit" to a reader of the body.
        const stated: ChecklistThreshold = {};
        if (threshold.maxOpen !== null) stated.maxOpen = threshold.maxOpen;
        if (threshold.minResolvedRatio !== null) stated.minResolvedRatio = threshold.minResolvedRatio;
        thresholds[severity] = stated;
    }
    return thresholds;
}

/**
 * The body the route reads for a draft the form accepted: **the kind's own keys and no other**, since
 * `ChecklistRule.parse` refuses a parameter another kind takes rather than ignoring it. `null` for "no
 * rule", which unbinds the line.
 */
export function ruleOf(draft: RuleDraft): ChecklistRule | null {
    if (!draft.kind) return null;
    const maxAgeDays = draft.maxAgeDays!;
    switch (draft.kind) {
        case 'dependency_analysis': {
            const rule: ChecklistRule = { kind: draft.kind, maxAgeDays, requireSchedule: draft.requireSchedule! };
            const thresholds = thresholdsOf(draft);
            if (Object.keys(thresholds).length > 0) rule.thresholds = thresholds;
            return rule;
        }
        case 'findings_threshold':
            return {
                kind: draft.kind,
                maxAgeDays,
                scopes: [...new Set(draft.scopes.map(normalizedScope))],
                thresholds: thresholdsOf(draft)
            };
        case 'coverage_threshold': {
            const rule: ChecklistRule = {
                kind: draft.kind,
                maxAgeDays,
                metric: draft.metric!,
                minimumRatio: draft.minimumRatio!,
                aggregation: draft.aggregation!
            };
            // Only when stated: a rule without one is the whole report, and keeps the digest it had.
            const scope = coverageScopeOf(draft);
            if (scope) rule.scope = scope;
            return rule;
        }
        case 'test_suite_passed':
            return {
                kind: draft.kind,
                maxAgeDays,
                suitePattern: draft.suitePattern.trim(),
                minimumTests: draft.minimumTests!
            };
        case 'component_versions':
            return {
                kind: draft.kind,
                maxAgeDays,
                components: draft.components.map((component): ChecklistAllowedComponent => ({
                    purlPrefix: component.purlPrefix.trim(),
                    versions: versionsOf(component)
                }))
            };
        case 'component_present':
            return {
                kind: draft.kind,
                maxAgeDays,
                components: draft.components.map((component): ChecklistAllowedComponent => ({
                    purlPrefix: component.purlPrefix.trim()
                }))
            };
    }
}

/**
 * A rule written the one way whatever order it was typed in: keys sorted, nulls dropped, scopes and
 * versions sorted, packages by prefix — the server's canonical form, near enough to tell a line the form
 * changed from one it only reopened. Only a changed line is sent: a line sent unchanged makes its sender
 * one of the draft's authors for nothing.
 */
export function canonicalRule(rule: ChecklistRule | null): string {
    if (!rule) return 'null';
    const copy: ChecklistRule = { ...rule };
    if (copy.scopes) copy.scopes = [...new Set(copy.scopes.map(normalizedScope))].sort();
    if (copy.scope) {
        const include = [...new Set(copy.scope.include ?? [])].sort();
        const exclude = [...new Set(copy.scope.exclude ?? [])].sort();
        copy.scope =
            include.length === 0 && exclude.length === 0
                ? null
                : { ...(include.length ? { include } : {}), ...(exclude.length ? { exclude } : {}) };
    }
    if (copy.components) {
        copy.components = copy.components
            .map((component) => ({
                purlPrefix: component.purlPrefix,
                versions: component.versions ? [...new Set(component.versions)].sort() : null
            }))
            .sort((a, b) => (a.purlPrefix < b.purlPrefix ? -1 : a.purlPrefix > b.purlPrefix ? 1 : 0));
    }
    return JSON.stringify(sortedValue(copy));
}

function sortedValue(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(sortedValue);
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value as Record<string, unknown>)
                .filter(([, entry]) => entry !== null && entry !== undefined)
                .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
                .map(([key, entry]) => [key, sortedValue(entry)])
        );
    }
    return value;
}

export function sameRule(a: ChecklistRule | null, b: ChecklistRule | null): boolean {
    return canonicalRule(a) === canonicalRule(b);
}

// ---------------------------------------------------------------------- in words

/** A ratio as a person reads it: 0.6 is 60, 0.3333 is 33.33. */
export function percentOf(ratio: number): string {
    return String(Math.round(ratio * 1_000_000) / 10_000);
}

export function ruleKindLabel(i18n: I18nService, kind: string): string {
    i18n.translations();
    const key = (RULE_KIND_KEYS as Record<string, string | undefined>)[kind];
    return key ? i18n.t(key) : kind;
}

export function severityLabel(i18n: I18nService, severity: string): string {
    i18n.translations();
    const key = (SEVERITY_KEYS as Record<string, string | undefined>)[severity];
    return key ? i18n.t(key) : severity;
}

/**
 * A scope in words: a built-in step by its finding type's label, a plugin and an imported tool by what
 * the organisation called them, `all` as the total a threshold was judged on.
 */
export function scopeLabel(i18n: I18nService, scope: string): string {
    i18n.translations();
    if (scope === 'all') return i18n.t('checklist_rules.scope_all');
    if (scope.startsWith('builtin:')) return findingTypeLabel(i18n, scope.slice('builtin:'.length));
    if (scope.startsWith('plugin:'))
        return i18n.t('checklist_rules.scope_plugin', { id: scope.slice('plugin:'.length) });
    const imported = /^import:([^/]+)\/(.*)$/.exec(scope);
    if (imported) return i18n.t('checklist_rules.scope_import', { source: imported[1], tool: imported[2] });
    return scope;
}

/** One severity's threshold in words, both halves when both are stated. */
function thresholdWords(i18n: I18nService, severity: string, threshold: ChecklistThreshold): string {
    const parts: string[] = [];
    if (threshold.maxOpen !== null && threshold.maxOpen !== undefined) {
        parts.push(i18n.t('checklist_rules.summary_max_open', { count: threshold.maxOpen }));
    }
    if (threshold.minResolvedRatio !== null && threshold.minResolvedRatio !== undefined) {
        parts.push(i18n.t('checklist_rules.summary_min_resolved', { percent: percentOf(threshold.minResolvedRatio) }));
    }
    return `${severityLabel(i18n, severity)} — ${parts.join(', ')}`;
}

/**
 * What a rule measures, a sentence per condition, in the reader's language: what the person binding it
 * reads beside the KPI's text, so that a disagreement between the two shows (§3, step 4), and what the
 * person answering reads beside the measurement.
 */
export function describeRule(i18n: I18nService, rule: ChecklistRule): string[] {
    i18n.translations();
    const lines: string[] = [];
    const thresholds = (): string[] =>
        SEVERITIES.filter((severity) => !!rule.thresholds?.[severity]).map((severity) =>
            thresholdWords(i18n, severity, rule.thresholds![severity]!)
        );
    switch (rule.kind) {
        case 'dependency_analysis':
            lines.push(
                rule.requireSchedule
                    ? i18n.t('checklist_rules.summary_schedule_required')
                    : i18n.t('checklist_rules.summary_schedule_not_required')
            );
            lines.push(...thresholds());
            break;
        case 'findings_threshold':
            lines.push(
                i18n.t('checklist_rules.summary_scopes', {
                    scopes: (rule.scopes ?? []).map((scope) => scopeLabel(i18n, scope)).join(', ')
                })
            );
            lines.push(...thresholds());
            break;
        case 'coverage_threshold':
            lines.push(
                i18n.t('checklist_rules.summary_coverage', {
                    metric: rule.metric ? i18n.t(METRIC_KEYS[rule.metric]) : '—',
                    percent:
                        rule.minimumRatio !== null && rule.minimumRatio !== undefined
                            ? percentOf(rule.minimumRatio)
                            : '—',
                    aggregation: rule.aggregation ? i18n.t(AGGREGATION_KEYS[rule.aggregation]) : '—'
                })
            );
            if (rule.scope?.include?.length) {
                lines.push(
                    i18n.t('checklist_rules.summary_scope_include', { patterns: rule.scope.include.join(', ') })
                );
            }
            if (rule.scope?.exclude?.length) {
                lines.push(
                    i18n.t('checklist_rules.summary_scope_exclude', { patterns: rule.scope.exclude.join(', ') })
                );
            }
            break;
        case 'test_suite_passed':
            lines.push(
                i18n.t('checklist_rules.summary_suite', {
                    pattern: rule.suitePattern ?? '',
                    tests: rule.minimumTests ?? 0
                })
            );
            break;
        case 'component_versions':
            for (const component of rule.components ?? []) {
                lines.push(
                    i18n.t('checklist_rules.summary_component', {
                        prefix: component.purlPrefix,
                        versions: (component.versions ?? []).join(', ')
                    })
                );
            }
            break;
        case 'component_present':
            for (const component of rule.components ?? []) {
                lines.push(i18n.t('checklist_rules.summary_component_present', { prefix: component.purlPrefix }));
            }
            break;
    }
    lines.push(i18n.t('checklist_rules.summary_age', { days: rule.maxAgeDays }));
    return lines;
}

/** The refusal in the reader's words. */
export function refusalMessage(i18n: I18nService, refusal: RuleRefusal): string {
    const params = { ...refusal.params };
    if (typeof params['severity'] === 'string') params['severity'] = severityLabel(i18n, params['severity']);
    return i18n.t(RULE_PROBLEM_KEYS[refusal.problem], params);
}
