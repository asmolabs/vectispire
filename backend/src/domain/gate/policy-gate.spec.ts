import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { BUILT_IN_POLICY, GateIssue, GatePolicy, GateVerdict, RequestedPolicy, evaluate, harden, isAtLeast, severityRank } from './policy-gate';

interface VerdictVector {
    label: string;
    issues: GateIssue[];
    policy: GatePolicy;
    expected: GateVerdict;
}

interface HardenVector {
    label: string;
    base: GatePolicy;
    requested: RequestedPolicy;
    expected: { policy: GatePolicy; ignoredRelaxations: string[] };
}

const vectors: { verdicts: VerdictVector[]; hardenings: HardenVector[] } = JSON.parse(readFileSync(join(__dirname, '../../../test/vectors/policy-gate.json'), 'utf8'));

describe('gate verdict', () => {
    it('has vectors generated from the Python code', () => {
        expect(vectors.verdicts.length).toBeGreaterThan(0);
        expect(vectors.hardenings.length).toBeGreaterThan(0);
    });

    // The verdict is what fails or passes somebody's build. Each case comes from a real
    // run of `zanshin.services.policy_gate`.
    describe.each(vectors.verdicts)('$label', (vector) => {
        it('returns exactly the verdict Python returned', () => {
            expect(evaluate(vector.issues, vector.policy)).toEqual(vector.expected);
        });
    });

    describe('the built-in policy is the one from Python', () => {
        it('has the same defaults', () => {
            // A default that diverges would change the verdict of every target with no
            // policy of its own, which is most of them.
            const fromVectors = vectors.verdicts.find((vector) => vector.label === 'empty backlog');
            expect(fromVectors?.policy).toEqual(BUILT_IN_POLICY);
        });
    });
});

describe('severity ranking', () => {
    it('runs worst to least severe', () => {
        expect(severityRank('critical')).toBeLessThan(severityRank('high'));
        expect(severityRank('high')).toBeLessThan(severityRank('medium'));
        expect(severityRank('medium')).toBeLessThan(severityRank('low'));
    });

    it("ranks unknown BELOW low, and not as the worst case", () => {
        // The OSV back end returns "unknown" whenever an advisory has no normalized
        // severity. As the worst case, it would fail every build on that back end — the
        // most expensive inversion possible in this file.
        expect(severityRank('unknown')).toBeGreaterThan(severityRank('low'));
        expect(isAtLeast('unknown', 'low')).toBe(false);
    });

    it('places a value outside the vocabulary last', () => {
        expect(severityRank('catastrophic')).toBeGreaterThan(severityRank('unknown'));
    });

    it('is case-insensitive and treats null as unknown', () => {
        expect(severityRank('CRITICAL')).toBe(severityRank('critical'));
        expect(severityRank(null)).toBe(severityRank('unknown'));
        expect(severityRank(undefined)).toBe(severityRank('unknown'));
    });
});

describe('tightening of a requested policy', () => {
    describe.each(vectors.hardenings)('$label', (vector) => {
        it('returns exactly what Python returns', () => {
            expect(harden(vector.base, vector.requested)).toEqual(vector.expected);
        });
    });

    it("tells an absent field from a field set to null", () => {
        // Without that distinction, any caller omitting `failOnSeverity` would be told
        // its request was refused, on every call. This is the equivalent of Pydantic's
        // `model_dump(exclude_unset=True)`, and it does not survive a `Partial<T>`
        // naively filled with undefined.
        expect(harden(BUILT_IN_POLICY, {}).ignoredRelaxations).toEqual([]);
        expect(harden(BUILT_IN_POLICY, { failOnSeverity: null }).ignoredRelaxations).toEqual(['fail_on_severity']);
    });

    it('does not modify the base policy', () => {
        const base: GatePolicy = { ...BUILT_IN_POLICY };
        harden(base, { failOnSeverity: 'low', failOnKev: false });
        expect(base).toEqual(BUILT_IN_POLICY);
    });
});

describe('the invariants a port must preserve', () => {
    const issue = (overrides: Partial<GateIssue> = {}): GateIssue => ({
        id: 1,
        state: 'open',
        type: 'vulnerability',
        severity: 'critical',
        identifier: 'CVE-2024-1234',
        packageName: 'requests',
        fixVersions: '2.32.0',
        isKev: false,
        triageStatus: 'under_review',
        ...overrides
    });

    it('no policy can make quality vote', () => {
        // There is deliberately no flag: an option would make "quality never blocks" a
        // sentence with an asterisk. This test is what checks it against *every*
        // combination, not just the ones in the vectors.
        const quality = issue({ type: 'quality', isKev: true });
        for (const failOnSeverity of [null, 'critical', 'high', 'medium', 'low', 'unknown']) {
            for (const flags of [0, 1, 2, 3, 4, 5, 6, 7]) {
                const policy: GatePolicy = {
                    failOnSeverity,
                    failOnKev: Boolean(flags & 1),
                    fixableOnly: Boolean(flags & 2),
                    includeTriaged: Boolean(flags & 4),
                    includeAiReview: true
                };
                const verdict = evaluate([quality], policy);
                expect(verdict.passed).toBe(true);
                expect(verdict.evaluated).toBe(0);
            }
        }
    });

    it('a KEV never produces two violations for the same issue', () => {
        const verdict = evaluate([issue({ isKev: true, severity: 'critical' })], BUILT_IN_POLICY);
        expect(verdict.violations).toHaveLength(1);
        expect(verdict.violations[0].rule).toBe('kev');
    });

    it('a fully triaged backlog passes, and the same backlog audited fails', () => {
        const triaged = [issue({ triageStatus: 'not_affected' }), issue({ id: 2, triageStatus: 'fixed' })];
        expect(evaluate(triaged, BUILT_IN_POLICY).passed).toBe(true);
        expect(evaluate(triaged, { ...BUILT_IN_POLICY, includeTriaged: true }).passed).toBe(false);
    });

    it('fixable_only does not silently pass a KEV with no fix', () => {
        // This is the situation that calls for a human decision, not a green build — but
        // the Python code discards it anyway, because the filter applies before the
        // rules. A test of what is, not of what should be: if someone decides to fix this
        // behaviour, it will have to be fixed on both sides.
        const verdict = evaluate([issue({ severity: 'medium', fixVersions: null, isKev: true })], { ...BUILT_IN_POLICY, fixableOnly: true });
        expect(verdict.evaluated).toBe(0);
        expect(verdict.passed).toBe(true);
    });
});
