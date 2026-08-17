/**
 * Throttling of login attempts.
 *
 * **Two independent counters, and both have to pass.** This is not redundancy: each one
 * alone has a hole the other closes.
 *
 * - Count per **user** only, and anybody can lock a colleague's account whose username
 *   they know — a denial of service at a third of the cost of an attack.
 * - Count per **client** only, and an attacker spread across several machines tries as
 *   many passwords as they like against one account.
 *
 * Hence two different thresholds: five attempts for a user, twenty for a client. A shared
 * workstation can legitimately see several people mistype; an account cannot.
 *
 * **The window slides rather than being fixed.** A fixed window resets on the hour, which
 * hands an attacker a free burst at the boundary.
 *
 * The check happens **before** any password comparison: a locked account must cost no
 * bcrypt rounds, otherwise the throttle itself becomes the lever for a denial of service.
 */

export const MAX_ATTEMPTS_PER_USER = 5;
export const MAX_ATTEMPTS_PER_CLIENT = 20;
/** 15 minutes, in milliseconds. */
export const WINDOW_MS = 15 * 60 * 1000;

export interface ThrottleDecision {
    allowed: boolean;
    /** Seconds to wait before another attempt; 0 when allowed. */
    retryAfterSeconds: number;
}

export interface AttemptCounts {
    /** The instants (epoch milliseconds) of this user's failures inside the window. */
    user: number[];
    /** Likewise for this client. */
    client: number[];
}

/**
 * The key under which a user's failures are counted.
 *
 * Normalized, otherwise "Alice", "alice" and "alice  " would be three counters and the
 * threshold would be worth three times as much to anyone bothering to vary the case.
 */
export function userKey(username: string): string {
    return `login:user:${username.trim().toLowerCase()}`;
}

export function clientKey(clientId: string): string {
    return `login:client:${clientId}`;
}

/**
 * Decides whether an attempt is allowed, and if not for how much longer.
 *
 * The delay is computed from the **oldest failure still inside the window**: that is the
 * instant the counter drops back below the threshold.
 */
export function decide(counts: AttemptCounts, now: number): ThrottleDecision {
    const waits = [waitFor(counts.user, MAX_ATTEMPTS_PER_USER, now), waitFor(counts.client, MAX_ATTEMPTS_PER_CLIENT, now)];
    const retryAfterSeconds = Math.max(...waits);
    return { allowed: retryAfterSeconds === 0, retryAfterSeconds };
}

function waitFor(attempts: number[], limit: number, now: number): number {
    const inWindow = attempts.filter((at) => now - at < WINDOW_MS);
    if (inWindow.length < limit) return 0;

    const earliest = Math.min(...inWindow);
    // Rounded up: announcing "0 seconds" while a fraction remains would make the caller
    // retry at once and fail again.
    return Math.max(1, Math.ceil((earliest + WINDOW_MS - now) / 1000));
}

/** Keeps only the attempts still inside the window. */
export function withinWindow(attempts: number[], now: number): number[] {
    return attempts.filter((at) => now - at < WINDOW_MS);
}
