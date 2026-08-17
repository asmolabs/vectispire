import { SESSION_IDLE_MS, SESSION_TTL_MS, Session, bearerToken, isActive, newSessionToken, stateOf, tokensMatch } from './session';

const NOW = 1_800_000_000_000;
const session = (over: Partial<Session> = {}): Session => ({
    token: 'jeton',
    userId: 1,
    username: 'alice',
    role: 'ADMIN',
    createdAt: NOW,
    lastSeenAt: NOW,
    mustChangePassword: false,
    ...over
});

describe('jeton de session', () => {
    it('is 43 base64url characters', () => {
        const token = newSessionToken();
        expect(token).toHaveLength(43);
        expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('does not repeat', () => {
        expect(new Set(Array.from({ length: 100 }, newSessionToken)).size).toBe(100);
    });

    it('ne porte aucune information', () => {
        // Not a JWT: nothing to decode, nothing that ages badly, and revocation needs no
        // demande pas de liste noire.
        expect(newSessionToken()).not.toContain('.');
    });
});

describe('cycle de vie', () => {
    it('is active while both lifetimes run', () => {
        expect(isActive(session(), NOW + 1000)).toBe(true);
    });

    it('expires at the absolute lifetime, even under active use', () => {
        // This is what bounds the use of a stolen token.
        expect(stateOf(session({ createdAt: NOW - SESSION_TTL_MS, lastSeenAt: NOW }), NOW)).toBe('expired');
    });

    it('closes after a prolonged silence', () => {
        expect(stateOf(session({ createdAt: NOW, lastSeenAt: NOW - SESSION_IDLE_MS }), NOW)).toBe('idle');
    });

    it('distingue les deux causes de fermeture', () => {
        expect(stateOf(session({ createdAt: NOW - SESSION_TTL_MS, lastSeenAt: NOW - SESSION_IDLE_MS }), NOW)).toBe('expired');
    });

    it("activity pushes back the idle closure, not the absolute expiry", () => {
        const refreshed = session({ createdAt: NOW - SESSION_TTL_MS + 1000, lastSeenAt: NOW });
        expect(stateOf(refreshed, NOW)).toBe('active');
        expect(stateOf(refreshed, NOW + 1000)).toBe('expired');
    });
});

describe('comparaison de jetons', () => {
    it('accepte deux jetons identiques', () => {
        const token = newSessionToken();
        expect(tokensMatch(token, token)).toBe(true);
    });

    it('refuses two different tokens', () => {
        expect(tokensMatch(newSessionToken(), newSessionToken())).toBe(false);
    });

    it('refuses without throwing on different lengths', () => {
        // `timingSafeEqual` throws if the lengths differ.
        expect(tokensMatch('court', newSessionToken())).toBe(false);
        expect(tokensMatch('', '')).toBe(true);
    });
});

describe('Authorization header', () => {
    it('extracts a well-formed token', () => {
        expect(bearerToken('Bearer abc123')).toBe('abc123');
        expect(bearerToken('  Bearer abc123  ')).toBe('abc123');
    });

    it.each([[null], [undefined], [''], ['abc123'], ['Basic abc123'], ['Bearer'], ['Bearer a b'], ['bearer abc123']])('rend null sur %p', (header) => {
        // Telling "absent", "malformed" and "unknown" apart would inform somebody
        // qui sonde, sans aider personne d'autre.
        expect(bearerToken(header as string | null | undefined)).toBeNull();
    });
});
