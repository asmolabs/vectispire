import { generateKey, InvalidApiKeyError, KEY_PREFIX, normalizeLifetime, normalizeScopes, normalizeTarget, PREFIX_LENGTH } from './api-key-rules';
import { DEFAULT_SCOPES } from './scopes';

describe('API key rules', () => {
    describe('generation', () => {
        it('produit le format que Python produisait', () => {
            const { fullKey, prefix } = generateKey();
            // `zsk_` + 43 base64url characters, like secrets.token_urlsafe(32).
            expect(fullKey).toMatch(/^zsk_[A-Za-z0-9_-]{43}$/);
            expect(prefix).toBe(fullKey.slice(0, PREFIX_LENGTH));
            expect(prefix).toHaveLength(12);
            expect(prefix.startsWith(`${KEY_PREFIX}_`)).toBe(true);
        });

        it('does not repeat a key', () => {
            const keys = new Set(Array.from({ length: 200 }, () => generateKey().fullKey));
            expect(keys.size).toBe(200);
        });

        it('stays under the 72 bytes bcrypt considers', () => {
            // Past that, the end of the key would not take part in the hash.
            expect(Buffer.byteLength(generateKey().fullKey, 'utf8')).toBeLessThanOrEqual(72);
        });
    });

    describe('scopes', () => {
        it("takes the broad defaults when nothing is requested", () => {
            expect(normalizeScopes(null)).toEqual([...DEFAULT_SCOPES]);
            expect(normalizeScopes([])).toEqual([...DEFAULT_SCOPES]);
        });

        it("n'accorde jamais « agent » implicitement", () => {
            // That scope grants the right to run scans.
            expect(normalizeScopes(null)).not.toContain('agent');
        });

        it('orders as declared, so two identical keys store the same string', () => {
            expect(normalizeScopes(['export', 'read'])).toEqual(['read', 'export']);
            expect(normalizeScopes(['read', 'export'])).toEqual(['read', 'export']);
        });

        it('refuses an unknown scope rather than ignoring it', () => {
            expect(() => normalizeScopes(['read', 'admin'])).toThrow(InvalidApiKeyError);
        });

        it('refuse une liste qui ne contient que du vide', () => {
            expect(() => normalizeScopes(['  ', ''])).toThrow(/could do nothing/);
        });
    });

    describe('restriction de cible', () => {
        it('accepte aucune restriction', () => {
            expect(normalizeTarget(null, null)).toEqual({ targetKind: null, targetId: null });
            expect(normalizeTarget('', '')).toEqual({ targetKind: null, targetId: null });
        });

        it('accepts a complete restriction', () => {
            expect(normalizeTarget('repository', 7)).toEqual({ targetKind: 'repository', targetId: 7 });
            expect(normalizeTarget('container', '3')).toEqual({ targetKind: 'container', targetId: 3 });
        });

        it('refuses half a restriction, which would give the impression of a bounded key', () => {
            expect(() => normalizeTarget('repository', null)).toThrow(InvalidApiKeyError);
            expect(() => normalizeTarget(null, 7)).toThrow(InvalidApiKeyError);
            expect(() => normalizeTarget('utilisateur', 7)).toThrow(InvalidApiKeyError);
        });
    });

    describe('lifetime', () => {
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
