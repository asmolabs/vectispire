import { randomBytes } from 'node:crypto';
import { ALL_SCOPES, DEFAULT_SCOPES } from './scopes';

/**
 * Une clé d'API : `zsk_<43 caractères>`, montrée une seule fois.
 *
 * Seule l'empreinte bcrypt est conservée. `prefix` garde les douze premiers caractères
 * **en clair** — ce n'est pas un secret, et cela permet de ne comparer par bcrypt que les
 * candidats de ce préfixe. Sans lui, chaque requête authentifiée par clé coûterait un
 * bcrypt par clé existante, soit un déni de service offert à qui présente n'importe quoi.
 *
 * La longueur du préfixe est celle de Python (`len("zsk") + 9`) et doit le rester : les
 * lignes existantes portent un préfixe de cette taille, et une requête qui en découperait
 * treize ne trouverait plus rien.
 */
export const KEY_PREFIX = 'zsk';
export const PREFIX_LENGTH = KEY_PREFIX.length + 9;

/** 32 octets en base64url — 43 caractères, comme `secrets.token_urlsafe(32)`. */
export function generateKey(): { fullKey: string; prefix: string } {
    const fullKey = `${KEY_PREFIX}_${randomBytes(32).toString('base64url')}`;
    return { fullKey, prefix: fullKey.slice(0, PREFIX_LENGTH) };
}

/**
 * Normalise une liste de portées, ou explique le refus.
 *
 * Les défauts restent larges — c'est ce dont disposait une clé émise avant l'existence
 * des portées, et un formulaire dont les défauts cassent la chaîne d'intégration de
 * l'appelant apprend surtout à tout cocher. Le resserrement est offert, pas imposé.
 */
export function normalizeScopes(scopes: readonly string[] | null | undefined): string[] {
    if (!scopes || scopes.length === 0) return [...DEFAULT_SCOPES];

    const cleaned = scopes.map((scope) => scope.trim()).filter(Boolean);
    const unknown = cleaned.filter((scope) => !(ALL_SCOPES as readonly string[]).includes(scope));
    if (unknown.length) throw new InvalidApiKeyError(`Portée(s) inconnue(s) : ${unknown.join(', ')}`);
    if (!cleaned.length) throw new InvalidApiKeyError("Une clé sans aucune portée ne pourrait rien faire.");

    // Dans l'ordre déclaré, pour que deux clés aux mêmes portées stockent la même chaîne.
    return ALL_SCOPES.filter((scope) => cleaned.includes(scope));
}

export interface TargetRestriction {
    targetKind: string | null;
    targetId: number | null;
}

/** Une restriction de cible est soit complète, soit absente — jamais à moitié. */
export function normalizeTarget(kind: unknown, id: unknown): TargetRestriction {
    const hasKind = typeof kind === 'string' && kind.trim() !== '';
    const hasId = id !== null && id !== undefined && id !== '';
    if (!hasKind && !hasId) return { targetKind: null, targetId: null };

    const cleanKind = hasKind ? (kind as string).trim() : '';
    const numericId = Number(id);
    if (!['repository', 'container'].includes(cleanKind) || !hasId || !Number.isInteger(numericId)) {
        // Une moitié de restriction serait pire qu'aucune : elle donnerait l'impression
        // d'une clé bornée alors qu'elle ne le serait pas.
        throw new InvalidApiKeyError("Restriction de cible invalide : « repository » ou « container » avec un identifiant.");
    }
    return { targetKind: cleanKind, targetId: numericId };
}

export function normalizeLifetime(expiresInDays: unknown): number | null {
    if (expiresInDays === null || expiresInDays === undefined || expiresInDays === '') return null;
    const days = Number(expiresInDays);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
        throw new InvalidApiKeyError("Durée de vie invalide : un nombre de jours entre 1 et 3650, ou rien.");
    }
    return days;
}

export class InvalidApiKeyError extends Error {}
