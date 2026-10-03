import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { I18nService } from '../core/i18n/i18n.service';
import {
    COVERAGE_CANONICAL,
    COVERAGE_RULE,
    SECRETS_CANONICAL,
    SECRETS_RULE
} from '../core/testing/checklists.fixtures';
import { asSchema } from '../core/testing/contract';
import { useEnglish } from '../core/testing/english';
import english from '../../../public/i18n/en.json';
import french from '../../../public/i18n/fr.json';
import {
    AGGREGATION_KEYS,
    canonicalRule,
    coveragePatternAllowed,
    describeRule,
    draftOf,
    emptyDraft,
    METRIC_KEYS,
    ratioAllowed,
    RULE_KIND_KEYS,
    RULE_PROBLEM_KEYS,
    ruleOf,
    ruleRefusal,
    type RuleDraft,
    scopeAllowed,
    versionsOf,
    secretsAtZero,
    SEVERITY_KEYS
} from './checklist-rules';

/**
 * The rules a checklist line is measured by, as the form reads them (decision 0032 §6). The bounds
 * are the server's — `ChecklistRule`, `SeverityThreshold`, `AllowedComponent`, `ToolScope` — each
 * pinned at both edges, since a bound off by one is a rule the form accepts and the route refuses,
 * or the other way round.
 */
describe('the checklist rules, as the form reads them', () => {
    const findings = (changes: Partial<RuleDraft> = {}): RuleDraft => ({
        ...secretsAtZero(),
        ...changes
    });
    const problem = (draft: RuleDraft) => ruleRefusal(draft)?.problem ?? null;

    it('asks every kind its maximum age, from 1 to 366 whole days, and proposes seven', () => {
        expect(emptyDraft('coverage_threshold').maxAgeDays).toBe(7);
        expect(emptyDraft(null).maxAgeDays).toBeNull();
        for (const [age, refused] of [
            [0, true],
            [1, false],
            [366, false],
            [367, true],
            [1.5, true],
            [null, true]
        ] as const) {
            expect(problem(findings({ maxAgeDays: age })), `${age} days`).toBe(refused ? 'max_age' : null);
        }
    });

    it('proposes nothing else: the schedule, the metric and the aggregation are stated or refused', () => {
        const dependency = emptyDraft('dependency_analysis');
        expect(problem(dependency)).toBe('require_schedule');
        expect(problem({ ...dependency, requireSchedule: false })).toBeNull();

        const coverage = { ...emptyDraft('coverage_threshold'), minimumRatio: 0.8 };
        expect(problem(coverage)).toBe('metric');
        expect(problem({ ...coverage, metric: 'line' })).toBe('aggregation');
        expect(problem({ ...coverage, metric: 'line', aggregation: 'project_weighted' })).toBeNull();
    });

    it('names 1 to 20 scopes a scan, a plugin or a declared source records, each once', () => {
        const scopes = (count: number) => Array.from({ length: count }, (_, index) => `plugin:tool-${index}`);
        expect(problem(findings({ scopes: [] }))).toBe('scopes_count');
        expect(problem(findings({ scopes: scopes(20) }))).toBeNull();
        expect(problem(findings({ scopes: scopes(21) }))).toBe('scopes_count');
        expect(problem(findings({ scopes: ['builtin:secret', 'builtin:secret'] }))).toBe('scope_twice');
        // Two spellings of one imported tool are one scope: the server keys its name in lower case.
        expect(problem(findings({ scopes: ['import:ci-server/Sonar', 'import:ci-server/sonar'] }))).toBe('scope_twice');
    });

    it.each([
        ['builtin:secret', true],
        ['builtin:license', true],
        ['builtin:ai_review', false],
        ['builtin:plugin', false],
        ['plugin:gitleaks-custom', true],
        ['plugin:ab', true],
        ['plugin:a', false],
        ['plugin:Gitleaks', false],
        ['plugin:-edge', false],
        [`plugin:${'a'.repeat(40)}`, true],
        [`plugin:${'a'.repeat(41)}`, false],
        ['import:quality-server/sonarqube', true],
        ['import:q/sonarqube', false],
        ['import:quality-server/', false],
        ['import:quality-server/a,b', false],
        [`import:quality-server/${'t'.repeat(100)}`, true],
        [`import:quality-server/${'t'.repeat(101)}`, false],
        ['sast', false]
    ])('takes %s as a scope: %s', (scope, allowed) => {
        expect(scopeAllowed(scope)).toBe(allowed);
    });

    it('asks a findings rule a threshold, and holds each to the server bounds', () => {
        const none = emptyDraft('findings_threshold');
        expect(problem({ ...none, scopes: ['builtin:sast'] })).toBe('threshold_needed');

        const withCritical = (maxOpen: number | null, minResolvedRatio: number | null = null) =>
            findings({
                thresholds: { ...secretsAtZero().thresholds, critical: { maxOpen, minResolvedRatio } }
            });
        expect(problem(withCritical(0))).toBeNull();
        expect(problem(withCritical(1_000_000))).toBeNull();
        expect(problem(withCritical(1_000_001))).toBe('max_open');
        expect(problem(withCritical(-1))).toBe('max_open');
        expect(problem(withCritical(1.5))).toBe('max_open');
        expect(problem(withCritical(null, 0))).toBeNull();
        expect(problem(withCritical(null, 1))).toBeNull();
        expect(problem(withCritical(null, 0.6))).toBeNull();
        expect(problem(withCritical(null, 0.1234))).toBeNull();
        expect(problem(withCritical(null, 0.12345))).toBe('resolved_ratio');
        expect(problem(withCritical(null, 1.01))).toBe('resolved_ratio');
        expect(problem(withCritical(null, -0.1))).toBe('resolved_ratio');
    });

    it('holds a coverage minimum above 0 and up to 1, four decimals at most', () => {
        expect(ratioAllowed(0, false)).toBe(false);
        expect(ratioAllowed(0, true)).toBe(true);
        expect(ratioAllowed(0.0001, false)).toBe(true);
        expect(ratioAllowed(0.00001, false)).toBe(false);
        expect(ratioAllowed(1, false)).toBe(true);
        expect(ratioAllowed(null, true)).toBe(false);
        const coverage: RuleDraft = {
            ...emptyDraft('coverage_threshold'),
            metric: 'branch',
            aggregation: 'per_repository'
        };
        expect(problem({ ...coverage, minimumRatio: 0 })).toBe('minimum_ratio');
        expect(problem({ ...coverage, minimumRatio: 1 })).toBeNull();
    });

    it("refuses a coverage scope's pattern as the server would, and takes both lists blank as the whole report", () => {
        const coverage = (changes: Partial<RuleDraft> = {}): RuleDraft => ({
            ...emptyDraft('coverage_threshold'),
            metric: 'line',
            minimumRatio: 0.8,
            aggregation: 'per_repository',
            ...changes
        });
        expect(problem(coverage())).toBeNull();
        expect(problem(coverage({ scopeInclude: '**/service/**, org/example/*-api' }))).toBeNull();
        expect(problem(coverage({ scopeExclude: '**/generated/**' }))).toBeNull();
        for (const refused of [
            'org.example.service',
            '**/serv**',
            'org/?/x',
            'src/{ab}',
            'src/[ab]',
            '/org/example',
            'org/example/',
            'org//example',
            'org\\example',
            'org/../x',
            'a/'.repeat(250) + 'a'
        ]) {
            expect(coveragePatternAllowed(refused), refused).toBe(false);
            expect(ruleRefusal(coverage({ scopeInclude: refused }))).toEqual({
                problem: 'coverage_pattern',
                params: { pattern: refused }
            });
        }
        expect(coveragePatternAllowed('a/'.repeat(249) + 'ab')).toBe(true);
        expect(problem(coverage({ scopeExclude: 'a/b, a/b' }))).toBe('coverage_pattern_twice');
        const many = Array.from({ length: 21 }, (_, at) => `p${at}/x`).join(', ');
        expect(problem(coverage({ scopeInclude: many }))).toBe('coverage_patterns_count');
        expect(problem(coverage({ scopeInclude: many.split(', ').slice(0, 20).join(', ') }))).toBeNull();
    });

    it('sends a coverage scope only when stated, each list only when it holds a pattern', () => {
        const draft: RuleDraft = {
            ...emptyDraft('coverage_threshold'),
            metric: 'line',
            minimumRatio: 0.8,
            aggregation: 'per_repository',
            scopeInclude: ' org/example/** , ',
            scopeExclude: ''
        };
        expect(asSchema('ChecklistRuleForm', ruleOf(draft))).toEqual({
            kind: 'coverage_threshold',
            maxAgeDays: 7,
            metric: 'line',
            minimumRatio: 0.8,
            aggregation: 'per_repository',
            scope: { include: ['org/example/**'] }
        });
        expect(ruleOf({ ...draft, scopeInclude: ' , ' })).not.toHaveProperty('scope');
        const reopened = draftOf({ ...COVERAGE_RULE, scope: { include: ['b/**', 'a/**'], exclude: ['**/gen/**'] } });
        expect(reopened.scopeInclude).toBe('b/**, a/**');
        expect(reopened.scopeExclude).toBe('**/gen/**');
        expect(canonicalRule(ruleOf(reopened))).toBe(
            canonicalRule({ ...COVERAGE_RULE, scope: { exclude: ['**/gen/**'], include: ['a/**', 'b/**'] } })
        );
        expect(canonicalRule({ ...COVERAGE_RULE, scope: null })).toBe(COVERAGE_CANONICAL);
    });

    it('asks a test rule a pattern of 1 to 500 characters and at least one test', () => {
        const suite: RuleDraft = { ...emptyDraft('test_suite_passed'), suitePattern: 'com.example.*', minimumTests: 1 };
        expect(problem(suite)).toBeNull();
        expect(problem({ ...suite, suitePattern: '  ' })).toBe('pattern');
        expect(problem({ ...suite, suitePattern: 'a'.repeat(500) })).toBeNull();
        expect(problem({ ...suite, suitePattern: 'a'.repeat(501) })).toBe('pattern');
        expect(problem({ ...suite, minimumTests: 0 })).toBe('minimum_tests');
        expect(problem({ ...suite, minimumTests: 10_000_000 })).toBeNull();
        expect(problem({ ...suite, minimumTests: 10_000_001 })).toBe('minimum_tests');
    });

    it('asks a component rule 1 to 50 packages, each a versionless package URL with 1 to 100 versions', () => {
        const one = (purlPrefix: string, versions = '1.0.0') => ({ purlPrefix, versions });
        const components = (list: { purlPrefix: string; versions: string }[]): RuleDraft => ({
            ...emptyDraft('component_versions'),
            components: list
        });
        expect(problem(components([]))).toBe('components_count');
        expect(problem(components([one('pkg:maven/com.example/ledger-core', '3.2.1, 3.3.0')]))).toBeNull();
        expect(problem(components(Array.from({ length: 50 }, (_, index) => one(`pkg:npm/lib-${index}`))))).toBeNull();
        expect(problem(components(Array.from({ length: 51 }, (_, index) => one(`pkg:npm/lib-${index}`))))).toBe(
            'components_count'
        );
        for (const prefix of ['maven/com.example/x', 'pkg:', 'pkg:npm/left@1.0', 'pkg:npm/left pad']) {
            expect(problem(components([one(prefix)])), prefix).toBe('purl');
        }
        expect(problem(components([one('pkg:npm/left'), one('pkg:npm/left')]))).toBe('purl_twice');
        expect(problem(components([one('pkg:npm/left', ' , ')]))).toBe('versions');
        const hundred = Array.from({ length: 100 }, (_, index) => `1.${index}`).join(',');
        expect(problem(components([one('pkg:npm/left', hundred)]))).toBeNull();
        expect(problem(components([one('pkg:npm/left', `${hundred},2.0`)]))).toBe('versions');
        expect(problem(components([one('pkg:npm/left', 'v'.repeat(256))]))).toBe('version_length');
    });

    it('splits typed versions on the commas between them, never on one inside a Maven range', () => {
        const typed = (versions: string) => versionsOf({ purlPrefix: 'pkg:maven/org.example/x', versions });
        expect(typed('[1.17,2.0), 1.16.4')).toEqual(['[1.17,2.0)', '1.16.4']);
        expect(typed('(,1.0],[1.2,1.3)')).toEqual(['(,1.0]', '[1.2,1.3)']);
        expect(typed(' 3.2.1 ,, 3.3.0 ')).toEqual(['3.2.1', '3.3.0']);
        expect(
            draftOf({
                kind: 'component_versions',
                maxAgeDays: 7,
                components: [{ purlPrefix: 'pkg:maven/org.example/x', versions: ['[1.17,2.0)', '1.16.4'] }]
            }).components[0].versions
        ).toBe('[1.17,2.0), 1.16.4');
    });

    it('refuses a range on a package that is not Maven, and leaves a Maven range for the server to read', () => {
        const draft = (purlPrefix: string, versions: string): RuleDraft => ({
            ...emptyDraft('component_versions'),
            components: [{ purlPrefix, versions }]
        });
        expect(problem(draft('pkg:npm/left-pad', '[1.0,2.0)'))).toBe('version_range');
        expect(problem(draft('pkg:npm/left-pad', '1.0.0'))).toBeNull();
        expect(problem(draft('pkg:maven/org.example.platform', '[1.17,2.0), 1.16.4'))).toBeNull();
    });

    it('asks a presence rule its packages alone, sends no versions, and says so in words', () => {
        const present = (list: string[]): RuleDraft => ({
            ...emptyDraft('component_present'),
            components: list.map((purlPrefix) => ({ purlPrefix, versions: '' }))
        });
        expect(problem(present([]))).toBe('components_count');
        expect(problem(present(['pkg:maven/org.example.platform']))).toBeNull();
        expect(problem(present(['pkg:maven/org.example.platform@1.0']))).toBe('purl');
        expect(problem(present(['pkg:maven/org.example', 'pkg:maven/org.example']))).toBe('purl_twice');
        const rule = ruleOf({
            ...present([' pkg:maven/org.example.platform ']),
            components: [{ purlPrefix: ' pkg:maven/org.example.platform ', versions: '1.0' }]
        });
        expect(asSchema('ChecklistRuleForm', rule)).toEqual({
            kind: 'component_present',
            maxAgeDays: 7,
            components: [{ purlPrefix: 'pkg:maven/org.example.platform' }]
        });
        expect(draftOf(rule).components).toEqual([{ purlPrefix: 'pkg:maven/org.example.platform', versions: '' }]);
        expect(canonicalRule(rule)).toBe(
            '{"components":[{"purlPrefix":"pkg:maven/org.example.platform"}],"kind":"component_present","maxAgeDays":7}'
        );
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
        useEnglish();
        expect(describeRule(TestBed.inject(I18nService), rule!)).toEqual([
            'pkg:maven/org.example.platform present, whatever its version',
            'Evidence at most 7 days old'
        ]);
    });

    it('proposes a change review in the words of its line — one peer, every change, thirty days — each one editable', () => {
        const review = emptyDraft('change_review');
        expect(review.minimumApprovals).toBe(1);
        expect(review.minimumRatio).toBe(1);
        expect(review.windowDays).toBe(30);
        expect(review.branch).toBe('');
        expect(problem(review)).toBeNull();
        // Blank is the default branch: the key is left out, never sent empty.
        expect(asSchema('ChecklistRuleForm', ruleOf(review))).toEqual({
            kind: 'change_review',
            maxAgeDays: 7,
            minimumApprovals: 1,
            windowDays: 30,
            minimumRatio: 1
        });
        expect(ruleOf({ ...review, branch: ' release/2026 ' })?.branch).toBe('release/2026');
        // No other kind is proposed these.
        expect(emptyDraft('coverage_threshold').minimumRatio).toBeNull();
    });

    it('holds a change review to the server bounds: 1 to 10 approvals, 1 to 366 days, a share above 0, a branch Git takes', () => {
        const review = emptyDraft('change_review');
        for (const [approvals, refused] of [
            [0, true],
            [1, false],
            [10, false],
            [11, true],
            [1.5, true],
            [null, true]
        ] as const) {
            expect(problem({ ...review, minimumApprovals: approvals }), `${approvals} approvals`).toBe(
                refused ? 'minimum_approvals' : null
            );
        }
        for (const [days, refused] of [
            [0, true],
            [1, false],
            [366, false],
            [367, true],
            [null, true]
        ] as const) {
            expect(problem({ ...review, windowDays: days }), `${days} days`).toBe(refused ? 'window_days' : null);
        }
        expect(problem({ ...review, minimumRatio: 0 })).toBe('review_share');
        expect(problem({ ...review, minimumRatio: 0.95 })).toBeNull();
        for (const branch of ['a b', 'a..b', 'a~1', 'x:y', 'x*', 'x[1', 'x\\y', 'x'.repeat(256)]) {
            expect(problem({ ...review, branch }), branch).toBe('branch');
        }
        expect(problem({ ...review, branch: 'release/2026' })).toBeNull();
    });

    it('allows "no rule" always: it unbinds the line', () => {
        expect(ruleRefusal(emptyDraft(null))).toBeNull();
        expect(ruleOf(emptyDraft(null))).toBeNull();
    });

    it("sends each kind's own parameters and no other, since the server refuses another kind's", () => {
        const keys = (draft: RuleDraft) => Object.keys(ruleOf(draft)!).sort();
        const everything: RuleDraft = {
            ...secretsAtZero(),
            requireSchedule: true,
            metric: 'line',
            minimumRatio: 0.8,
            aggregation: 'per_repository',
            suitePattern: 'x*',
            minimumTests: 3,
            components: [{ purlPrefix: 'pkg:npm/left', versions: '1.0.0' }]
        };
        expect(keys({ ...everything, kind: 'dependency_analysis' })).toEqual([
            'kind',
            'maxAgeDays',
            'requireSchedule',
            'thresholds'
        ]);
        expect(keys({ ...everything, kind: 'findings_threshold' })).toEqual([
            'kind',
            'maxAgeDays',
            'scopes',
            'thresholds'
        ]);
        expect(keys({ ...everything, kind: 'coverage_threshold' })).toEqual([
            'aggregation',
            'kind',
            'maxAgeDays',
            'metric',
            'minimumRatio'
        ]);
        expect(keys({ ...everything, kind: 'test_suite_passed' })).toEqual([
            'kind',
            'maxAgeDays',
            'minimumTests',
            'suitePattern'
        ]);
        expect(keys({ ...everything, kind: 'component_versions' })).toEqual(['components', 'kind', 'maxAgeDays']);
        expect(keys({ ...everything, kind: 'component_present' })).toEqual(['components', 'kind', 'maxAgeDays']);
        expect(
            keys({ ...everything, kind: 'change_review', minimumApprovals: 1, windowDays: 30, branch: 'main' })
        ).toEqual(['branch', 'kind', 'maxAgeDays', 'minimumApprovals', 'minimumRatio', 'windowDays']);
        // A dependency rule without thresholds says none, rather than an empty object.
        expect(ruleOf({ ...emptyDraft('dependency_analysis'), requireSchedule: false })).toEqual({
            kind: 'dependency_analysis',
            maxAgeDays: 7,
            requireSchedule: false
        });
    });

    it('states only the halves of a threshold given: a blank maxOpen is left out, never sent as null', () => {
        const draft = findings();
        draft.thresholds.medium = { maxOpen: null, minResolvedRatio: 0.6 };
        expect(asSchema('ChecklistRuleForm', ruleOf(draft))).toEqual({
            kind: 'findings_threshold',
            maxAgeDays: 7,
            scopes: ['builtin:secret'],
            thresholds: { critical: { maxOpen: 0 }, high: { maxOpen: 0 }, medium: { minResolvedRatio: 0.6 } }
        });
    });

    it('offers the secrets-at-zero preset as decision 0032 words it, written as the server writes it', () => {
        const rule = ruleOf(secretsAtZero());
        expect(rule).toEqual(SECRETS_RULE);
        expect(canonicalRule(rule)).toBe(SECRETS_CANONICAL);
        expect(canonicalRule(COVERAGE_RULE)).toBe(COVERAGE_CANONICAL);
    });

    it('reopens a bound rule unchanged as the same rule: the form sends nothing for it', () => {
        expect(canonicalRule(ruleOf(draftOf(COVERAGE_RULE)))).toBe(COVERAGE_CANONICAL);
        expect(canonicalRule(ruleOf(draftOf(SECRETS_RULE)))).toBe(SECRETS_CANONICAL);
    });

    it('writes a rule in words, every condition and the age, in the reader language', () => {
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
        useEnglish();
        const i18n = TestBed.inject(I18nService);
        expect(describeRule(i18n, SECRETS_RULE)).toEqual([
            'Every scope looked on every repository: Exposed secret',
            'Critical — at most 0 open',
            'High — at most 0 open',
            'Evidence at most 7 days old'
        ]);
        expect(describeRule(i18n, COVERAGE_RULE)).toEqual([
            'Coverage of lines at least 80 %, on every repository',
            'Evidence at most 14 days old'
        ]);
        expect(
            describeRule(i18n, {
                ...COVERAGE_RULE,
                scope: { include: ['org/example/**'], exclude: ['**/generated/**'] }
            })
        ).toEqual([
            'Coverage of lines at least 80 %, on every repository',
            'Only the packages matching org/example/**',
            'Except the packages matching **/generated/**',
            'Evidence at most 14 days old'
        ]);
        expect(
            describeRule(i18n, {
                kind: 'change_review',
                maxAgeDays: 1,
                minimumApprovals: 2,
                windowDays: 30,
                minimumRatio: 0.95,
                branch: 'release/2026'
            })
        ).toEqual([
            'At least 95 % of the changes merged in the last 30 days approved by at least 2 people other than their author — or a forge configuration requiring it',
            'Changes merged into release/2026',
            'Evidence at most 1 days old'
        ]);
        TestBed.resetTestingModule();
    });

    it('has every label its maps name, in both languages — keys the i18n check cannot count', () => {
        const lookup = (bundle: unknown, key: string) =>
            key
                .split('.')
                .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
        for (const map of [RULE_KIND_KEYS, SEVERITY_KEYS, METRIC_KEYS, AGGREGATION_KEYS, RULE_PROBLEM_KEYS]) {
            for (const key of Object.values(map)) {
                expect(typeof lookup(english, key), `${key} in English`).toBe('string');
                expect(typeof lookup(french, key), `${key} in French`).toBe('string');
            }
        }
    });
});
