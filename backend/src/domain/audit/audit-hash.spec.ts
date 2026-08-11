import { AuditEntryForHash, AuditEntryForVerification, computeEntryHash, rebuildChain, verifyChain } from './audit-hash';

describe('empreinte d’une entrée du journal d’audit', () => {
    describe('canonicalisation', () => {
        const base: AuditEntryForHash = {
            previousHash: null,
            timestamp: new Date('2026-01-02T03:04:05.123Z'),
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Connexion réussie'
        };

        it('dépend de l’instant et non de la façon dont il a été construit', () => {
            // Deux `Date` construits différemment pour le même instant : la forme
            // canonique est en UTC, donc l'empreinte ne dépend pas du fuseau de la
            // machine qui la calcule. C'est la propriété qui compte pour un contrôle
            // vérifiable ailleurs que là où il a été écrit.
            const sameInstant = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 123));
            expect(computeEntryHash({ ...base, timestamp: sameInstant })).toBe(computeEntryHash(base));
        });

        it('distingue deux instants à la milliseconde', () => {
            expect(computeEntryHash({ ...base, timestamp: new Date('2026-01-02T03:04:05.124Z') })).not.toBe(computeEntryHash(base));
        });

        it('distingue une absence d’horodatage', () => {
            expect(computeEntryHash({ ...base, timestamp: null })).not.toBe(computeEntryHash(base));
        });
    });

    describe('sensibilité au contenu', () => {
        const base: AuditEntryForHash = {
            previousHash: null,
            timestamp: new Date('2026-08-10T08:13:58.322Z'),
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Connexion réussie'
        };

        it.each([['operationType'], ['resourceId'], ['userId'], ['ipAddress'], ['userAgent'], ['description'], ['previousHash'], ['timestamp']] as const)('change si %s change', (field) => {
            const altered: AuditEntryForHash = { ...base };
            // Une milliseconde d'écart, et non une microseconde : la forme canonique
            // s'arrête à la milliseconde, ce que le bloc précédent vérifie en propre.
            if (field === 'timestamp') altered.timestamp = new Date('2026-08-10T08:13:58.323Z');
            else (altered as unknown as Record<string, unknown>)[field] = 'modifié';
            expect(computeEntryHash(altered)).not.toBe(computeEntryHash(base));
        });

        it('traite null et chaîne vide comme équivalents', () => {
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
                timestamp: new Date(Date.UTC(2026, 7, 10, 8, 0, i)),
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

describe('reconstruction de la chaîne', () => {
    /**
     * Des entrées portant des empreintes d'une autre formule — cohérentes entre elles et
     * fausses pour celle-ci. C'est la situation d'un journal repris d'une version
     * antérieure : la reconstruction doit le rendre vérifiable sans toucher au contenu.
     */
    function foreignFormula(count: number): AuditEntryForVerification[] {
        return Array.from({ length: count }, (_, index) => ({
            id: `entry-${index}`,
            // Des empreintes d'une autre formule : présentes, cohérentes entre elles,
            // et fausses pour celle-ci.
            previousHash: index === 0 ? null : `ancienne-${index - 1}`,
            entryHash: `ancienne-${index}`,
            timestamp: new Date(Date.UTC(2026, 7, 10, 8, 0, index)),
            operationType: 'SETTING_UPDATED',
            resourceId: String(index),
            userId: 'admin',
            ipAddress: null,
            userAgent: null,
            description: `Modification ${index}`
        }));
    }

    it('rend vérifiable un historique venu de l’ancienne formule', () => {
        const entries = foreignFormula(5);
        expect(verifyChain(entries).broken).not.toBeNull();

        rebuildChain(entries);

        expect(verifyChain(entries)).toEqual({ broken: null, unverifiable: 0 });
    });

    it('ne touche pas au contenu des entrées', () => {
        // Réécrire un journal d'intégrité est déjà assez ; en réécrire le contenu
        // serait exactement ce que ce journal existe pour rendre détectable.
        const entries = foreignFormula(3);
        const before = entries.map((entry) => ({ ...entry, previousHash: undefined, entryHash: undefined }));

        rebuildChain(entries);

        expect(entries.map((entry) => ({ ...entry, previousHash: undefined, entryHash: undefined }))).toEqual(before);
    });

    it('repart de zéro : la première entrée n’a pas de précédente', () => {
        const [first] = rebuildChain(foreignFormula(3));
        expect(first.previousHash).toBeNull();
    });

    it('est idempotente', () => {
        // Relancée par erreur, elle doit rendre exactement la même chaîne.
        const once = rebuildChain(foreignFormula(4)).map((entry) => entry.entryHash);
        const twice = rebuildChain(rebuildChain(foreignFormula(4))).map((entry) => entry.entryHash);
        expect(twice).toEqual(once);
    });
});
