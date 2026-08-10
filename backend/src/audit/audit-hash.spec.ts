import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AuditEntryForHash, AuditEntryForVerification, computeEntryHash, verifyChain } from './audit-hash';

interface AuditVector {
    label: string;
    entry: AuditEntryForHash;
    postgresRendering: string;
    expected: string;
}

const vectors: AuditVector[] = JSON.parse(readFileSync(join(__dirname, '../../test/vectors/audit-hash.json'), 'utf8'));

describe('empreinte d’une entrée du journal d’audit', () => {
    it('dispose de vecteurs générés depuis le code Python', () => {
        expect(vectors.length).toBeGreaterThan(0);
    });

    describe.each(vectors)('$label', (vector) => {
        it("reproduit l'empreinte calculée par Python", () => {
            expect(computeEntryHash(vector.entry)).toBe(vector.expected);
        });

        it('donne le même résultat depuis le rendu brut de PostgreSQL', () => {
            // C'est la forme réelle : les entrées vérifiées viennent de la base, pas
            // d'un objet déjà normalisé.
            expect(computeEntryHash({ ...vector.entry, timestamp: vector.postgresRendering })).toBe(vector.expected);
        });
    });

    describe('sensibilité au contenu', () => {
        const base: AuditEntryForHash = {
            previousHash: null,
            timestamp: '2026-08-10T08:13:58.322451',
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Connexion réussie'
        };

        it.each([['operationType'], ['resourceId'], ['userId'], ['ipAddress'], ['userAgent'], ['description'], ['previousHash'], ['timestamp']] as const)('change si %s change', (field) => {
            const altered: AuditEntryForHash = { ...base };
            altered[field] = field === 'timestamp' ? '2026-08-10T08:13:58.322452' : 'modifié';
            expect(computeEntryHash(altered)).not.toBe(computeEntryHash(base));
        });

        it('traite null et chaîne vide comme équivalents, comme Python', () => {
            expect(computeEntryHash({ ...base, userAgent: null })).toBe(computeEntryHash({ ...base, userAgent: '' }));
        });

        it('ne laisse pas un contenu imiter une frontière de champ', () => {
            // Le séparateur NUL existe pour ça : déplacer du texte d'un champ au
            // suivant doit changer l'empreinte.
            const a = computeEntryHash({ ...base, resourceId: 'ab', userId: 'cd' });
            const b = computeEntryHash({ ...base, resourceId: 'a', userId: 'bcd' });
            expect(a).not.toBe(b);
        });
    });
});

describe('vérification de la chaîne', () => {
    function chained(count: number): AuditEntryForVerification[] {
        const entries: AuditEntryForVerification[] = [];
        let previousHash: string | null = null;
        for (let i = 0; i < count; i += 1) {
            const entry: AuditEntryForVerification = {
                id: `entry-${i}`,
                previousHash,
                timestamp: `2026-08-10T08:00:0${i}.000001`,
                operationType: 'SETTING_UPDATED',
                resourceId: String(i),
                userId: 'admin',
                ipAddress: null,
                userAgent: null,
                description: `Modification ${i}`,
                entryHash: null
            };
            entry.entryHash = computeEntryHash(entry);
            previousHash = entry.entryHash;
            entries.push(entry);
        }
        return entries;
    }

    it('accepte une chaîne intacte', () => {
        expect(verifyChain(chained(5))).toEqual({ broken: null, unverifiable: 0 });
    });

    it('accepte une chaîne vide', () => {
        expect(verifyChain([])).toEqual({ broken: null, unverifiable: 0 });
    });

    it("signale une entrée dont le contenu a été modifié après coup", () => {
        const entries = chained(5);
        entries[2].description = 'Description réécrite';
        expect(verifyChain(entries).broken).toContain('entry-2');
        expect(verifyChain(entries).broken).toContain('ne correspond plus');
    });

    it('signale une entrée supprimée', () => {
        const entries = chained(5);
        entries.splice(2, 1);
        expect(verifyChain(entries).broken).toContain('entry-3');
        expect(verifyChain(entries).broken).toContain('supprimée');
    });

    it("compte sans les refuser les entrées antérieures au chaînage", () => {
        // Elles ne portent pas d'empreinte parce qu'elles précèdent la fonctionnalité,
        // pas parce qu'on y a touché.
        const entries = chained(3);
        const legacy: AuditEntryForVerification = { ...entries[0], id: 'legacy', entryHash: null, previousHash: null };
        expect(verifyChain([legacy, ...entries])).toEqual({ broken: null, unverifiable: 1 });
    });

    it('refuse une entrée sans empreinte insérée après le début du chaînage', () => {
        const entries = chained(3);
        entries.splice(2, 0, { ...entries[0], id: 'inserée', entryHash: null });
        expect(verifyChain(entries).broken).toContain('inserée');
        expect(verifyChain(entries).broken).toContain('insérée ou modifiée');
    });
});
