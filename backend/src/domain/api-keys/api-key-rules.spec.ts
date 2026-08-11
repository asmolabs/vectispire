import { generateKey, InvalidApiKeyError, KEY_PREFIX, normalizeLifetime, normalizeScopes, normalizeTarget, PREFIX_LENGTH } from './api-key-rules';
import { DEFAULT_SCOPES } from './scopes';

describe('règles de clé d’API', () => {
    describe('génération', () => {
        it('produit le format que Python produisait', () => {
            const { fullKey, prefix } = generateKey();
            // `zsk_` + 43 caractères base64url, comme secrets.token_urlsafe(32).
            expect(fullKey).toMatch(/^zsk_[A-Za-z0-9_-]{43}$/);
            expect(prefix).toBe(fullKey.slice(0, PREFIX_LENGTH));
            expect(prefix).toHaveLength(12);
            expect(prefix.startsWith(`${KEY_PREFIX}_`)).toBe(true);
        });

        it('ne répète pas une clé', () => {
            const keys = new Set(Array.from({ length: 200 }, () => generateKey().fullKey));
            expect(keys.size).toBe(200);
        });

        it('tient sous les 72 octets que bcrypt considère', () => {
            // Au-delà, la fin de la clé ne participerait pas à l'empreinte.
            expect(Buffer.byteLength(generateKey().fullKey, 'utf8')).toBeLessThanOrEqual(72);
        });
    });

    describe('portées', () => {
        it("prend les défauts larges quand rien n'est demandé", () => {
            expect(normalizeScopes(null)).toEqual([...DEFAULT_SCOPES]);
            expect(normalizeScopes([])).toEqual([...DEFAULT_SCOPES]);
        });

        it("n'accorde jamais « agent » implicitement", () => {
            // Ce périmètre donne le droit d'exécuter des scans.
            expect(normalizeScopes(null)).not.toContain('agent');
        });

        it('ordonne comme déclaré, pour que deux clés identiques stockent la même chaîne', () => {
            expect(normalizeScopes(['export', 'read'])).toEqual(['read', 'export']);
            expect(normalizeScopes(['read', 'export'])).toEqual(['read', 'export']);
        });

        it('refuse une portée inconnue plutôt que de l’ignorer', () => {
            expect(() => normalizeScopes(['read', 'admin'])).toThrow(InvalidApiKeyError);
        });

        it('refuse une liste qui ne contient que du vide', () => {
            expect(() => normalizeScopes(['  ', ''])).toThrow(/rien faire/);
        });
    });

    describe('restriction de cible', () => {
        it('accepte aucune restriction', () => {
            expect(normalizeTarget(null, null)).toEqual({ targetKind: null, targetId: null });
            expect(normalizeTarget('', '')).toEqual({ targetKind: null, targetId: null });
        });

        it('accepte une restriction complète', () => {
            expect(normalizeTarget('repository', 7)).toEqual({ targetKind: 'repository', targetId: 7 });
            expect(normalizeTarget('container', '3')).toEqual({ targetKind: 'container', targetId: 3 });
        });

        it('refuse une moitié de restriction, qui donnerait l’impression d’une clé bornée', () => {
            expect(() => normalizeTarget('repository', null)).toThrow(InvalidApiKeyError);
            expect(() => normalizeTarget(null, 7)).toThrow(InvalidApiKeyError);
            expect(() => normalizeTarget('utilisateur', 7)).toThrow(InvalidApiKeyError);
        });
    });

    describe('durée de vie', () => {
        it('accepte rien, ou un nombre de jours plausible', () => {
            expect(normalizeLifetime(null)).toBeNull();
            expect(normalizeLifetime('')).toBeNull();
            expect(normalizeLifetime(90)).toBe(90);
        });

        it.each([[0], [-1], [3651], [1.5], ['beaucoup']])('refuse %p', (value) => {
            expect(() => normalizeLifetime(value)).toThrow(InvalidApiKeyError);
        });
    });
});
