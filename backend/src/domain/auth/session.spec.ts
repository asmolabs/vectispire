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
    it('fait 43 caractères base64url', () => {
        const token = newSessionToken();
        expect(token).toHaveLength(43);
        expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('ne se répète pas', () => {
        expect(new Set(Array.from({ length: 100 }, newSessionToken)).size).toBe(100);
    });

    it('ne porte aucune information', () => {
        // Pas un JWT : rien à déchiffrer, rien qui périme mal, et la révocation ne
        // demande pas de liste noire.
        expect(newSessionToken()).not.toContain('.');
    });
});

describe('cycle de vie', () => {
    it('est active tant que les deux durées courent', () => {
        expect(isActive(session(), NOW + 1000)).toBe(true);
    });

    it('expire à la durée absolue, même en pleine activité', () => {
        // C'est ce qui borne l'usage d'un jeton volé.
        expect(stateOf(session({ createdAt: NOW - SESSION_TTL_MS, lastSeenAt: NOW }), NOW)).toBe('expired');
    });

    it('se ferme après un silence prolongé', () => {
        expect(stateOf(session({ createdAt: NOW, lastSeenAt: NOW - SESSION_IDLE_MS }), NOW)).toBe('idle');
    });

    it('distingue les deux causes de fermeture', () => {
        expect(stateOf(session({ createdAt: NOW - SESSION_TTL_MS, lastSeenAt: NOW - SESSION_IDLE_MS }), NOW)).toBe('expired');
    });

    it("l'activité repousse la fermeture pour inactivité, pas l'expiration absolue", () => {
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

    it('refuse deux jetons différents', () => {
        expect(tokensMatch(newSessionToken(), newSessionToken())).toBe(false);
    });

    it('refuse sans lever sur des longueurs différentes', () => {
        // `timingSafeEqual` lève si les longueurs diffèrent.
        expect(tokensMatch('court', newSessionToken())).toBe(false);
        expect(tokensMatch('', '')).toBe(true);
    });
});

describe('en-tête Authorization', () => {
    it('extrait un jeton bien formé', () => {
        expect(bearerToken('Bearer abc123')).toBe('abc123');
        expect(bearerToken('  Bearer abc123  ')).toBe('abc123');
    });

    it.each([[null], [undefined], [''], ['abc123'], ['Basic abc123'], ['Bearer'], ['Bearer a b'], ['bearer abc123']])('rend null sur %p', (header) => {
        // Distinguer « absent », « mal formé » et « inconnu » renseignerait quelqu'un
        // qui sonde, sans aider personne d'autre.
        expect(bearerToken(header as string | null | undefined)).toBeNull();
    });
});
