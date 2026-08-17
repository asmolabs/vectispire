import { BUILT_IN_POLICY } from './policy-gate';
import { PolicyLookup, SOURCE_BUILT_IN, SOURCE_GLOBAL, SOURCE_TARGET, StoredPolicy, describeSource, resolvePolicy } from './policy-resolution';

const globalPolicy: StoredPolicy = { ...BUILT_IN_POLICY, failOnSeverity: 'medium', version: 3 };
const targetPolicy: StoredPolicy = { ...BUILT_IN_POLICY, failOnSeverity: 'low', fixableOnly: true, version: 7 };

const lookup = (over: Partial<PolicyLookup> = {}): PolicyLookup => ({ forTarget: null, global: null, ...over });

describe('résolution de la politique applicable', () => {
    it('prend celle de la cible quand elle existe', () => {
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy, global: globalPolicy }));

        expect(resolved.source).toBe(SOURCE_TARGET);
        expect(resolved.version).toBe(7);
        expect(resolved.policy.failOnSeverity).toBe('low');
    });

    it('remplace entièrement la globale, sans fusionner', () => {
        // Une politique à moitié héritée est impossible à raisonner quand une
        // compilation échoue ; « les règles de ce dépôt » doit se lire à un seul endroit.
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

    it('retombe sur la politique intégrée quand rien n’est stocké', () => {
        const resolved = resolvePolicy(lookup());

        expect(resolved.source).toBe(SOURCE_BUILT_IN);
        expect(resolved.version).toBeNull();
        expect(resolved.policy).toEqual(BUILT_IN_POLICY);
    });

    it('ne va pas chercher une politique de cible sur la portée globale', () => {
        // Interroger la portée globale doit rendre la globale, même si une cible en a
        // une plus stricte — sans quoi l'écran des politiques mentirait sur le défaut.
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy, global: globalPolicy }), undefined, false);

        expect(resolved.source).toBe(SOURCE_GLOBAL);
        expect(resolved.version).toBe(3);
    });

    it('ne laisse pas la version d’une politique fuir dans la politique rendue', () => {
        const resolved = resolvePolicy(lookup({ global: globalPolicy }));
        expect(resolved.policy).not.toHaveProperty('version');
    });
});

describe('durcissement par la requête', () => {
    it('applique un durcissement demandé', () => {
        const resolved = resolvePolicy(lookup({ global: globalPolicy }), { failOnSeverity: 'low' });

        expect(resolved.policy.failOnSeverity).toBe('low');
        expect(resolved.ignoredRelaxations).toEqual([]);
    });

    it('refuse un assouplissement et le dit', () => {
        // C'est un contrôle de sécurité : sans lui, n'importe quel pipeline rendrait
        // vert ce qu'il veut depuis le corps de sa requête. Le refus est renvoyé plutôt
        // qu'appliqué en silence — un pipeline qui croit avoir désactivé une règle doit
        // l'apprendre.
        const resolved = resolvePolicy(lookup({ global: globalPolicy }), { failOnSeverity: null, failOnKev: false });

        expect(resolved.policy.failOnSeverity).toBe('medium');
        expect(resolved.policy.failOnKev).toBe(true);
        expect(resolved.ignoredRelaxations).toEqual(['fail_on_severity', 'fail_on_kev']);
    });

    it('conserve la provenance après durcissement', () => {
        // Le pipeline doit savoir contre quoi il a été évalué, pas seulement ce qu'on
        // lui a refusé.
        const resolved = resolvePolicy(lookup({ forTarget: targetPolicy }), { failOnSeverity: 'critical' });

        expect(resolved.source).toBe(SOURCE_TARGET);
        expect(resolved.version).toBe(7);
    });

    it('durcit aussi la politique intégrée', () => {
        const resolved = resolvePolicy(lookup(), { includeTriaged: true });
        expect(resolved.policy.includeTriaged).toBe(true);
        expect(resolved.source).toBe(SOURCE_BUILT_IN);
    });
});

describe('description de la provenance', () => {
    it('nomme la portée et la version', () => {
        expect(describeSource({ source: SOURCE_TARGET, version: 7 })).toBe("the target's policy v7");
        expect(describeSource({ source: SOURCE_GLOBAL, version: 3 })).toBe('the global policy v3');
    });

    it('ne prétend pas qu’une politique intégrée a une version', () => {
        expect(describeSource({ source: SOURCE_BUILT_IN, version: null })).toBe("the application's default policy");
    });
});
