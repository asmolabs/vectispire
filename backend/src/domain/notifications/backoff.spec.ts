import { BASE_BACKOFF_SECONDS, MAX_ATTEMPTS, MAX_BACKOFF_SECONDS, backoffSeconds, nextAttempt, recordableError } from './backoff';

describe('backoffSeconds', () => {
    it('doubles on each attempt then caps', () => {
        expect([1, 2, 3, 4].map(backoffSeconds)).toEqual([60, 120, 240, 480]);
        expect(backoffSeconds(20)).toBe(MAX_BACKOFF_SECONDS);
    });

    it('returns the base delay for an absurd value', () => {
        expect(backoffSeconds(0)).toBe(BASE_BACKOFF_SECONDS);
        expect(backoffSeconds(-3)).toBe(BASE_BACKOFF_SECONDS);
    });
});

describe('nextAttempt', () => {
    const now = new Date('2026-08-13T10:00:00Z');

    it('replanifie tant que le plafond de tentatives n\'est pas atteint', () => {
        const outcome = nextAttempt(1, now);

        expect(outcome.abandoned).toBe(false);
        expect(outcome.nextAttemptAt).toEqual(new Date('2026-08-13T10:01:00Z'));
    });

    it('abandonne au plafond', () => {
        // An endpoint that has refused eight times over several hours will not accept the
        // ninth, and a queue that never drains hides what could still go out.
        const outcome = nextAttempt(MAX_ATTEMPTS, now);

        expect(outcome.abandoned).toBe(true);
        expect(outcome.nextAttemptAt).toBeNull();
    });
});

describe('recordableError', () => {
    it("tronque une erreur bavarde", () => {
        // La page d'erreur HTML d'un proxy ne vaut pas un kilooctet par tentative dans une
        // table written on every scan.
        expect(recordableError(new Error('x'.repeat(2000))).length).toBe(500);
    });

    it('garde le nom du type, qui est souvent le seul indice utile', () => {
        expect(recordableError(new TypeError('fetch failed'))).toBe('TypeError: fetch failed');
    });
});
