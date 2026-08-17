import { randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * A session's rules.
 *
 * **What the Reflex version could not do.** Authentication state lived in the server
 * state there, indexed by a token the browser kept in `localStorage`: that token never
 * expired on its own, and `logout()` could not invalidate it — it merely cleared
 * server-side variables. There was no revocable session, hence no way to log anybody out.
 *
 * Three properties, each of them previously absent:
 *
 * 1. **Revocable.** A session is an entry in a store; deleting it really does log the user
 *    out, including from another device.
 * 2. **Expiring.** An absolute lifetime, and an idle lifetime. The absolute one bounds
 *    what a stolen token allows; the idle one closes forgotten sessions.
 * 3. **Opaque.** The token carries no information — no JWT, so nothing to decode, nothing
 *    that ages badly, and revocation needs no blocklist.
 */

/** Absolute lifetime, whatever happens. */
export const SESSION_TTL_MS = Number(process.env.ZANSHIN_SESSION_TTL_HOURS ?? 12) * 60 * 60 * 1000;

/** Past this much silence, the session closes even if its absolute lifetime still runs. */
export const SESSION_IDLE_MS = Number(process.env.ZANSHIN_SESSION_IDLE_MINUTES ?? 60) * 60 * 1000;

/** 32 bytes of entropy: 43 characters in base64url, nothing to escape. */
const TOKEN_BYTES = 32;

export interface Session {
    token: string;
    userId: number;
    username: string;
    role: string;
    /** Epoch milliseconds. */
    createdAt: number;
    lastSeenAt: number;
    /** The account must change its password before reaching anything else. */
    mustChangePassword: boolean;
}

export function newSessionToken(): string {
    return randomBytes(TOKEN_BYTES).toString('base64url');
}

export type SessionState = 'active' | 'expired' | 'idle';

/**
 * A session's state at a given instant.
 *
 * The two causes of closure are told apart because the operator tuning the durations needs
 * to know which one is actually closing their users' sessions.
 */
export function stateOf(session: Pick<Session, 'createdAt' | 'lastSeenAt'>, now: number): SessionState {
    if (now - session.createdAt >= SESSION_TTL_MS) return 'expired';
    if (now - session.lastSeenAt >= SESSION_IDLE_MS) return 'idle';
    return 'active';
}

export function isActive(session: Pick<Session, 'createdAt' | 'lastSeenAt'>, now: number): boolean {
    return stateOf(session, now) === 'active';
}

/**
 * Compares two tokens in constant time.
 *
 * An ordinary comparison stops at the first differing byte, and its duration reveals how
 * many bytes were already correct. Hardly exploitable over a network, and closing the door
 * costs nothing.
 */
export function tokensMatch(candidate: string, expected: string): boolean {
    const a = Buffer.from(candidate);
    const b = Buffer.from(expected);
    // `timingSafeEqual` requires equal lengths; a different length is a refusal anyway,
    // and revealing it teaches nothing useful.
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

/**
 * Extracts the token from an `Authorization` header.
 *
 * Returns `null` for anything that is not exactly `Bearer <token>`: telling "absent",
 * "malformed" and "unknown" apart would inform someone probing, without helping anybody
 * else.
 */
export function bearerToken(header: string | null | undefined): string | null {
    if (!header) return null;
    const match = /^Bearer (\S+)$/.exec(header.trim());
    return match ? match[1] : null;
}
