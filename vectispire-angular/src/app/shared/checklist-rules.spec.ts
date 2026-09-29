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
    describeRule,
    draftOf,
    emptyDraft,
    METRIC_KEYS,
    parseBoundRule,
    ratioAllowed,
    RULE_KIND_KEYS,
    RULE_PROBLEM_KEYS,
    ruleOf,
    ruleRefusal,
    type RuleDraft,
    scopeAllowed,
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

    it('takes a bound rule as the server sends it, structured', () => {
        expect(parseBoundRule(COVERAGE_RULE)).toBe(COVERAGE_RULE);
    });

    it('reads a bound rule from its canonical text, and nothing from text that is none', () => {
        expect(parseBoundRule(SECRETS_CANONICAL)).toEqual(SECRETS_RULE);
        expect(parseBoundRule(null)).toBeNull();
        expect(parseBoundRule('{')).toBeNull();
        expect(parseBoundRule('"findings_threshold"')).toBeNull();
        // Reopened and kept unchanged, a rule is the same rule: the form sends nothing for it.
        expect(canonicalRule(ruleOf(draftOf(parseBoundRule(COVERAGE_CANONICAL))))).toBe(COVERAGE_CANONICAL);
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
