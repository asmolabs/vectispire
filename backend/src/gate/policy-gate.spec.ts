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

const vectors: { verdicts: VerdictVector[]; hardenings: HardenVector[] } = JSON.parse(readFileSync(join(__dirname, '../../test/vectors/policy-gate.json'), 'utf8'));

describe('verdict du gate', () => {
    it('dispose de vecteurs générés depuis le code Python', () => {
        expect(vectors.verdicts.length).toBeGreaterThan(0);
        expect(vectors.hardenings.length).toBeGreaterThan(0);
    });

    // Le verdict est ce qui fait échouer ou passer la compilation de quelqu'un.
    // Chaque cas vient de l'exécution réelle de `zanshin.services.policy_gate`.
    describe.each(vectors.verdicts)('$label', (vector) => {
        it('rend exactement le verdict de Python', () => {
            expect(evaluate(vector.issues, vector.policy)).toEqual(vector.expected);
        });
    });

    describe('la politique intégrée est celle de Python', () => {
        it('a les mêmes défauts', () => {
            // Un défaut qui diverge changerait le verdict de toutes les cibles sans
            // politique propre, c'est-à-dire de la plupart.
            const fromVectors = vectors.verdicts.find((vector) => vector.label === 'backlog vide');
            expect(fromVectors?.policy).toEqual(BUILT_IN_POLICY);
        });
    });
});

describe('classement des sévérités', () => {
    it('va du pire au moins grave', () => {
        expect(severityRank('critical')).toBeLessThan(severityRank('high'));
        expect(severityRank('high')).toBeLessThan(severityRank('medium'));
        expect(severityRank('medium')).toBeLessThan(severityRank('low'));
    });

    it("classe « unknown » SOUS « low », et non en pire cas", () => {
        // Le backend OSV renvoie « unknown » dès qu'un avis n'a pas de sévérité
        // normalisée. En pire cas, il ferait échouer toutes les compilations sur ce
        // backend — l'inversion la plus coûteuse possible dans ce fichier.
        expect(severityRank('unknown')).toBeGreaterThan(severityRank('low'));
        expect(isAtLeast('unknown', 'low')).toBe(false);
    });

    it('range une valeur hors vocabulaire en dernier', () => {
        expect(severityRank('catastrophique')).toBeGreaterThan(severityRank('unknown'));
    });

    it('est insensible à la casse et traite null comme unknown', () => {
        expect(severityRank('CRITICAL')).toBe(severityRank('critical'));
        expect(severityRank(null)).toBe(severityRank('unknown'));
        expect(severityRank(undefined)).toBe(severityRank('unknown'));
    });
});

describe('durcissement d’une politique demandée', () => {
    describe.each(vectors.hardenings)('$label', (vector) => {
        it('rend exactement ce que rend Python', () => {
            expect(harden(vector.base, vector.requested)).toEqual(vector.expected);
        });
    });

    it("distingue « champ absent » de « champ à null »", () => {
        // Sans cette distinction, tout appelant omettant `failOnSeverity` s'entendrait
        // répondre que sa requête a été refusée, à chaque appel. C'est l'équivalent du
        // `model_dump(exclude_unset=True)` de Pydantic, et il ne survit pas à un
        // `Partial<T>` naïvement rempli de undefined.
        expect(harden(BUILT_IN_POLICY, {}).ignoredRelaxations).toEqual([]);
        expect(harden(BUILT_IN_POLICY, { failOnSeverity: null }).ignoredRelaxations).toEqual(['fail_on_severity']);
    });

    it('ne modifie pas la politique de base', () => {
        const base: GatePolicy = { ...BUILT_IN_POLICY };
        harden(base, { failOnSeverity: 'low', failOnKev: false });
        expect(base).toEqual(BUILT_IN_POLICY);
    });
});

describe('les invariants qu’un portage doit préserver', () => {
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

    it('aucune politique ne peut faire voter la qualité', () => {
        // Il n'y a délibérément pas de drapeau : une option ferait de « la qualité ne
        // bloque jamais » une phrase à astérisque. Ce test est ce qui le vérifie face
        // à *toutes* les combinaisons, et pas seulement celles des vecteurs.
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

    it('un KEV ne produit jamais deux violations pour le même problème', () => {
        const verdict = evaluate([issue({ isKev: true, severity: 'critical' })], BUILT_IN_POLICY);
        expect(verdict.violations).toHaveLength(1);
        expect(verdict.violations[0].rule).toBe('kev');
    });

    it('un backlog entièrement trié passe, et le même backlog audité échoue', () => {
        const triaged = [issue({ triageStatus: 'not_affected' }), issue({ id: 2, triageStatus: 'fixed' })];
        expect(evaluate(triaged, BUILT_IN_POLICY).passed).toBe(true);
        expect(evaluate(triaged, { ...BUILT_IN_POLICY, includeTriaged: true }).passed).toBe(false);
    });

    it('fixable_only ne fait pas passer un KEV sans correctif en silence', () => {
        // C'est la situation qui demande une décision humaine, pas une compilation
        // verte — mais le code Python l'écarte quand même, parce que le filtre
        // s'applique avant les règles. Test de constat, pas de souhait : si quelqu'un
        // décide de corriger ce comportement, il faudra le corriger des deux côtés.
        const verdict = evaluate([issue({ severity: 'medium', fixVersions: null, isKev: true })], { ...BUILT_IN_POLICY, fixableOnly: true });
        expect(verdict.evaluated).toBe(0);
        expect(verdict.passed).toBe(true);
    });
});
