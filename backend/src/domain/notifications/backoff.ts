/**
 * The outbox's retry policy.
 *
 * Exponential backoff, capped, then abandonment. Every term in that sentence is a decision:
 *
 * - **Backoff**, because the two realistic failures are a briefly unreachable webhook and a
 *   misconfigured one. Retrying the first quickly is right; retrying the second every sixty
 *   seconds indefinitely turns a typo into a permanent load.
 * - **Capped attempts**, because an endpoint that has refused eight times over several
 *   hours will not accept the ninth, and a queue that never drains hides, behind those
 *   messages, the ones that could still go out.
 * - **Abandoned, not deleted.** A message nobody will ever receive is exactly what an
 *   operator has to be able to find: it stays, with its last error.
 */

/** Eight attempts over a widening window: about four hours in total. */
export const MAX_ATTEMPTS = 8;
export const BASE_BACKOFF_SECONDS = 60;
export const MAX_BACKOFF_SECONDS = 3600;

/**
 * How many messages one pass sends.
 *
 * Maintenance does other work too; a burst of two hundred webhooks would starve all of it.
 */
export const MAX_PER_PASS = 20;

/** Delivered messages are kept for a few days, so that "did it go out?" has an answer. */
export const SENT_RETENTION_DAYS = 7;

/**
 * `60, 120, 240, …` capped at one hour.
 *
 * Computed from the attempt count rather than stored, so the policy can change with no
 * migration and without rows carrying an older version's schedule.
 */
export function backoffSeconds(attempts: number): number {
    if (attempts <= 0) return BASE_BACKOFF_SECONDS;
    return Math.min(BASE_BACKOFF_SECONDS * 2 ** (attempts - 1), MAX_BACKOFF_SECONDS);
}

/** The error as it will be kept: truncated. */
export function recordableError(error: unknown): string {
    const value = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    // Truncated: a proxy's HTML error page is not worth a kilobyte per attempt in a table
    // written on every scan.
    return value.slice(0, 500);
}

/** The outcome of a failed attempt: abandonment, or another chance at such a date. */
export function nextAttempt(attempts: number, now: Date): { abandoned: boolean; nextAttemptAt: Date | null } {
    if (attempts >= MAX_ATTEMPTS) return { abandoned: true, nextAttemptAt: null };
    return { abandoned: false, nextAttemptAt: new Date(now.getTime() + backoffSeconds(attempts) * 1000) };
}
