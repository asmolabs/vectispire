import { AuditEntryForHash, AuditEntryForVerification, computeEntryHash, rebuildChain, verifyChain } from './audit-hash';

describe('empreinte d’une entrée du journal d’audit', () => {
    describe("indépendance vis-à-vis du rendu des dates", () => {
        // La raison d'être de la reconstruction : l'ancienne formule hachait le format
        // de `datetime.isoformat()`, si bien que « .123 » et « .123000 » — le même
        // instant, rendu différemment selon le moteur — donnaient deux empreintes.
        const base: AuditEntryForHash = {
            previousHash: null,
            timestamp: '2026-01-02 03:04:05.123',
            operationType: 'LOGIN_SUCCESS',
            resourceId: 'alice',
            userId: 'alice',
            ipAddress: '10.0.0.4',
            userAgent: 'Mozilla/5.0',
            description: 'Connexion réussie'
        };

        it.each([
            ['fraction tronquée par PostgreSQL', '2026-01-02 03:04:05.123'],
            ['fraction complète', '2026-01-02 03:04:05.123000'],
            ['séparateur T', '2026-01-02T03:04:05.123000'],
            ['suffixe de fuseau UTC', '2026-01-02 03:04:05.123+00:00'],
            ['suffixe Z', '2026-01-02T03:04:05.123Z']
        ])('%s donne la même empreinte', (_label, timestamp) => {
            expect(computeEntryHash({ ...base, timestamp })).toBe(computeEntryHash(base));
        });

        it('ignore ce qui se trouve sous la milliseconde', () => {
            // Compromis assumé : la chaîne ne certifie plus l'ordre en deçà, ce dont
            // rien ne dépendait — deux entrées de la même milliseconde restent
            // distinguées par leur contenu et par l'empreinte de la précédente.
            expect(computeEntryHash({ ...base, timestamp: '2026-01-02 03:04:05.123001' })).toBe(computeEntryHash(base));
            expect(computeEntryHash({ ...base, timestamp: '2026-01-02 03:04:05.124' })).not.toBe(computeEntryHash(base));
        });

        it('distingue une absence d’horodatage', () => {
            expect(computeEntryHash({ ...base, timestamp: null })).not.toBe(computeEntryHash(base));
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
            // Une milliseconde d'écart, et non une microseconde : la forme canonique
            // s'arrête à la milliseconde, ce que le bloc précédent vérifie en propre.
            altered[field] = field === 'timestamp' ? '2026-08-10T08:13:58.323451' : 'modifié';
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

describe('reconstruction de la chaîne', () => {
    /**
     * L'opération de bascule : les entrées écrites par l'implémentation Python portent
     * des empreintes calculées sur l'ancienne formule et ne se vérifient plus.
     */
    function pythonEra(count: number): AuditEntryForVerification[] {
        return Array.from({ length: count }, (_, index) => ({
            id: `entry-${index}`,
            // Des empreintes d'une autre formule : présentes, cohérentes entre elles,
            // et fausses pour celle-ci.
            previousHash: index === 0 ? null : `ancienne-${index - 1}`,
            entryHash: `ancienne-${index}`,
            timestamp: `2026-08-10T08:00:0${index}.000001`,
            operationType: 'SETTING_UPDATED',
            resourceId: String(index),
            userId: 'admin',
            ipAddress: null,
            userAgent: null,
            description: `Modification ${index}`
        }));
    }

    it('rend vérifiable un historique venu de l’ancienne formule', () => {
        const entries = pythonEra(5);
        expect(verifyChain(entries).broken).not.toBeNull();

        rebuildChain(entries);

        expect(verifyChain(entries)).toEqual({ broken: null, unverifiable: 0 });
    });

    it('ne touche pas au contenu des entrées', () => {
        // Réécrire un journal d'intégrité est déjà assez ; en réécrire le contenu
        // serait exactement ce que ce journal existe pour rendre détectable.
        const entries = pythonEra(3);
        const before = entries.map((entry) => ({ ...entry, previousHash: undefined, entryHash: undefined }));

        rebuildChain(entries);

        expect(entries.map((entry) => ({ ...entry, previousHash: undefined, entryHash: undefined }))).toEqual(before);
    });

    it('repart de zéro : la première entrée n’a pas de précédente', () => {
        const [first] = rebuildChain(pythonEra(3));
        expect(first.previousHash).toBeNull();
    });

    it('est idempotente', () => {
        // Relancée par erreur, elle doit rendre exactement la même chaîne.
        const once = rebuildChain(pythonEra(4)).map((entry) => entry.entryHash);
        const twice = rebuildChain(rebuildChain(pythonEra(4))).map((entry) => entry.entryHash);
        expect(twice).toEqual(once);
    });
});
