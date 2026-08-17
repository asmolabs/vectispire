import { MAX_ATTEMPTS_PER_CLIENT, MAX_ATTEMPTS_PER_USER, WINDOW_MS, clientKey, decide, userKey, withinWindow } from './login-throttle';

const NOW = 1_800_000_000_000;
const attempts = (count: number, at = NOW) => Array.from({ length: count }, () => at);

describe('limitation des tentatives', () => {
    it('laisse passer en dessous des deux seuils', () => {
        expect(decide({ user: attempts(4), client: attempts(19) }, NOW)).toEqual({ allowed: true, retryAfterSeconds: 0 });
    });

    it('bloque au seuil utilisateur', () => {
        // Without this counter, an attacker spread across several machines would try as
        // many passwords as they liked against one account.
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER), client: [] }, NOW);
        expect(decision.allowed).toBe(false);
        expect(decision.retryAfterSeconds).toBe(WINDOW_MS / 1000);
    });

    it('bloque au seuil client', () => {
        // Without that counter, an attacker would try five passwords per account
        // sur toute la liste des utilisateurs.
        expect(decide({ user: [], client: attempts(MAX_ATTEMPTS_PER_CLIENT) }, NOW).allowed).toBe(false);
    });

    it('has a higher client threshold, because a workstation can be shared', () => {
        expect(MAX_ATTEMPTS_PER_CLIENT).toBeGreaterThan(MAX_ATTEMPTS_PER_USER);
    });

    it('announces the delay of the most constraining counter', () => {
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER, NOW - 60_000), client: attempts(MAX_ATTEMPTS_PER_CLIENT, NOW) }, NOW);
        expect(decision.retryAfterSeconds).toBe(WINDOW_MS / 1000);
    });
});

describe('sliding window', () => {
    it('forgets attempts that have left the window', () => {
        const old = attempts(MAX_ATTEMPTS_PER_USER, NOW - WINDOW_MS - 1);
        expect(decide({ user: old, client: [] }, NOW).allowed).toBe(true);
    });

    it('releases gradually, with no burst at a window boundary', () => {
        // A fixed window would hand an attacker a free burst on the hour.
        const staggered = [NOW - WINDOW_MS - 1, NOW - 10_000, NOW - 9_000, NOW - 8_000, NOW - 7_000];
        expect(decide({ user: staggered, client: [] }, NOW).allowed).toBe(true);
    });

    it('computes the delay from the oldest failure still counted', () => {
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER, NOW - WINDOW_MS + 30_000), client: [] }, NOW);
        expect(decision.retryAfterSeconds).toBe(30);
    });

    it('never announces zero seconds to a blocked caller', () => {
        // Announcing "0" would make the caller retry at once and fail again.
        const decision = decide({ user: attempts(MAX_ATTEMPTS_PER_USER, NOW - WINDOW_MS + 100), client: [] }, NOW);
        expect(decision.allowed).toBe(false);
        expect(decision.retryAfterSeconds).toBeGreaterThan(0);
    });

    it('filters the attempts worth keeping', () => {
        expect(withinWindow([NOW - WINDOW_MS - 1, NOW - 1000, NOW], NOW)).toEqual([NOW - 1000, NOW]);
    });
});

describe('counter keys', () => {
    it('normalise l’identifiant utilisateur', () => {
        // Sinon « Alice », « alice » et « alice  » seraient trois compteurs, et le seuil
        // vaudrait trois fois plus pour qui varie la casse.
        expect(userKey('  Alice  ')).toBe(userKey('alice'));
        expect(userKey('ALICE')).toBe('login:user:alice');
    });

    it('keeps the two namespaces apart', () => {
        expect(userKey('x')).not.toBe(clientKey('x'));
    });
});
