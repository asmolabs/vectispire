import { randomBytes } from 'node:crypto';
import { ALL_SCOPES, DEFAULT_SCOPES } from './scopes';

/**
 * An API key: `zsk_<43 characters>`, shown once.
 *
 * Only the bcrypt hash is kept. `prefix` keeps the first twelve characters
 * **en clair** — ce n'est pas un secret, et cela permet de ne comparer par bcrypt que les
 * candidates by that prefix. Without it, every key-authenticated request would cost one
 * bcrypt per existing key — a denial of service handed to anyone presenting anything.
 *
 * The prefix length is Python's (`len("zsk") + 9`) and must stay so: existing rows carry a
 * prefix of that size, and a query slicing
 * treize ne trouverait plus rien.
 */
export const KEY_PREFIX = 'zsk';
export const PREFIX_LENGTH = KEY_PREFIX.length + 9;

/** 32 bytes in base64url — 43 characters, like `secrets.token_urlsafe(32)`. */
export function generateKey(): { fullKey: string; prefix: string } {
    const fullKey = `${KEY_PREFIX}_${randomBytes(32).toString('base64url')}`;
    return { fullKey, prefix: fullKey.slice(0, PREFIX_LENGTH) };
}

/**
 * Normalizes a list of scopes, or explains the refusal.
 *
 * The defaults stay broad — that is what a key issued before scopes existed had, and a form
 * whose defaults break the caller's pipeline mostly teaches them to tick everything.
 * Narrowing is offered, not imposed.
 */
export function normalizeScopes(scopes: readonly string[] | null | undefined): string[] {
    if (!scopes || scopes.length === 0) return [...DEFAULT_SCOPES];

    const cleaned = scopes.map((scope) => scope.trim()).filter(Boolean);
    const unknown = cleaned.filter((scope) => !(ALL_SCOPES as readonly string[]).includes(scope));
    if (unknown.length) throw new InvalidApiKeyError(`Unknown scope(s): ${unknown.join(', ')}`);
    if (!cleaned.length) throw new InvalidApiKeyError('A key with no scope at all could do nothing.');

    // In declared order, so two keys with the same scopes store the same string.
    return ALL_SCOPES.filter((scope) => cleaned.includes(scope));
}

export interface TargetRestriction {
    targetKind: string | null;
    targetId: number | null;
}

/** A target restriction is either complete or absent — never half of one. */
export function normalizeTarget(kind: unknown, id: unknown): TargetRestriction {
    const hasKind = typeof kind === 'string' && kind.trim() !== '';
    const hasId = id !== null && id !== undefined && id !== '';
    if (!hasKind && !hasId) return { targetKind: null, targetId: null };

    const cleanKind = hasKind ? (kind as string).trim() : '';
    const numericId = Number(id);
    if (!['repository', 'container'].includes(cleanKind) || !hasId || !Number.isInteger(numericId)) {
        // Half a restriction would be worse than none: it would give the impression of a
        // bounded key when it was not.
        throw new InvalidApiKeyError("Restriction de cible invalide : « repository » ou « container » avec un identifiant.");
    }
    return { targetKind: cleanKind, targetId: numericId };
}

export function normalizeLifetime(expiresInDays: unknown): number | null {
    if (expiresInDays === null || expiresInDays === undefined || expiresInDays === '') return null;
    const days = Number(expiresInDays);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
        throw new InvalidApiKeyError('Invalid lifetime: a number of days between 1 and 3650, or nothing.');
    }
    return days;
}

export class InvalidApiKeyError extends Error {}
