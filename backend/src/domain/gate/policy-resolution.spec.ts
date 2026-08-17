import { BUILT_IN_POLICY } from './policy-gate';
import { PolicyLookup, SOURCE_BUILT_IN, SOURCE_GLOBAL, SOURCE_TARGET, StoredPolicy, describeSource, resolvePolicy } from './policy-resolution';

const globalPolicy: StoredPolicy = { ...BUILT_IN_POLICY, failOnSeverity: 'medium', version: 3 };
const targetPolicy: StoredPolicy = { ...BUILT_IN_POLICY, failOnSeverity: 'low', fixableOnly: true, version: 7 };

const lookup = (over: Partial<PolicyLookup> = {}): PolicyLookup => ({ forTarget: null, global: null, ...over });

describe('resolution of the applicable policy', () => {
    it('prend celle de la cible quand elle existe', () => {
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy, global: globalPolicy }));

        expect(resolved.source).toBe(SOURCE_TARGET);
        expect(resolved.version).toBe(7);
        expect(resolved.policy.failOnSeverity).toBe('low');
    });

    it('replaces the global one entirely, without merging', () => {
        // A half-inherited policy is impossible to reason about when a build fails; "this
        // repository's rules" must be readable in one single place.
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy, global: { ...globalPolicy, failOnKev: false, includeTriaged: true } }));

        expect(resolved.policy.failOnKev).toBe(targetPolicy.failOnKev);
        expect(resolved.policy.includeTriaged).toBe(targetPolicy.includeTriaged);
    });

    it('retombe sur la globale quand la cible n’a pas la sienne', () => {
        const resolved = resolvePolicy(lookup({ global: globalPolicy }));

        expect(resolved.source).toBe(SOURCE_GLOBAL);
        expect(resolved.version).toBe(3);
        expect(resolved.policy.failOnSeverity).toBe('medium');
    });

    it('falls back to the built-in policy when nothing is stored', () => {
        const resolved = resolvePolicy(lookup());

        expect(resolved.source).toBe(SOURCE_BUILT_IN);
        expect(resolved.version).toBeNull();
        expect(resolved.policy).toEqual(BUILT_IN_POLICY);
    });

    it('does not go looking for a target policy on the global scope', () => {
        // Querying the global scope must return the global one, even if a target has a
        // stricter one — otherwise the policies screen would lie about the default.
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy, global: globalPolicy }), undefined, false);

        expect(resolved.source).toBe(SOURCE_GLOBAL);
        expect(resolved.version).toBe(3);
    });

    it('ne laisse pas la version d’une politique fuir dans la politique rendue', () => {
        const resolved = resolvePolicy(lookup({ global: globalPolicy }));
        expect(resolved.policy).not.toHaveProperty('version');
    });
});

describe('tightening by the request', () => {
    it('applies a requested tightening', () => {
        const resolved = resolvePolicy(lookup({ global: globalPolicy }), { failOnSeverity: 'low' });

        expect(resolved.policy.failOnSeverity).toBe('low');
        expect(resolved.ignoredRelaxations).toEqual([]);
    });

    it('refuse un assouplissement et le dit', () => {
        // This is a security control: without it, any pipeline would turn whatever it
        // liked green from its own request body. The refusal is reported rather than
        // applied silently — a pipeline that believes it has disabled a rule needs to
        // l'apprendre.
        const resolved = resolvePolicy(lookup({ global: globalPolicy }), { failOnSeverity: null, failOnKev: false });

        expect(resolved.policy.failOnSeverity).toBe('medium');
        expect(resolved.policy.failOnKev).toBe(true);
        expect(resolved.ignoredRelaxations).toEqual(['fail_on_severity', 'fail_on_kev']);
    });

    it('keeps the provenance after tightening', () => {
        // The pipeline needs to know what it was evaluated against, not only what was
        // refused to it.
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy }), { failOnSeverity: 'critical' });

        expect(resolved.source).toBe(SOURCE_TARGET);
        expect(resolved.version).toBe(7);
    });

    it('tightens the built-in policy too', () => {
        const resolved = resolvePolicy(lookup(), { includeTriaged: true });
        expect(resolved.policy.includeTriaged).toBe(true);
        expect(resolved.source).toBe(SOURCE_BUILT_IN);
    });
});

describe('description de la provenance', () => {
    it('names the scope and the version', () => {
        expect(describeSource({ source: SOURCE_TARGET, version: 7 })).toBe("the target's policy v7");
        expect(describeSource({ source: SOURCE_GLOBAL, version: 3 })).toBe('the global policy v3');
    });

    it('does not pretend a built-in policy has a version', () => {
        expect(describeSource({ source: SOURCE_BUILT_IN, version: null })).toBe("the application's default policy");
    });
});
