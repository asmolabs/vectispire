import { randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Les règles d'une session.
 *
 * **Ce que la version Reflex ne pouvait pas faire.** L'état d'authentification y vivait
 * dans l'état serveur, indexé par un jeton que le navigateur gardait en `localStorage` :
 * ce jeton n'expirait jamais de lui-même, et `logout()` ne pouvait pas l'invalider — il
 * se contentait de vider des variables côté serveur. Il n'existait aucune session
 * révocable, donc aucun moyen de déconnecter quelqu'un.
 *
 * Trois propriétés, chacune absente auparavant :
 *
 * 1. **Révocable.** Une session est une entrée dans un magasin ; la supprimer déconnecte
 *    réellement, y compris depuis un autre appareil.
 * 2. **Expirante.** Une durée absolue, et une durée d'inactivité. L'absolue borne ce
 *    qu'un jeton volé permet ; celle d'inactivité ferme les sessions oubliées.
 * 3. **Opaque.** Le jeton ne porte aucune information — pas de JWT, donc rien à
 *    déchiffrer, rien qui périme mal, et la révocation ne demande pas de liste noire.
 */

/** Durée de vie absolue, quoi qu'il arrive. */
export const SESSION_TTL_MS = Number(process.env.ZANSHIN_SESSION_TTL_HOURS ?? 12) * 60 * 60 * 1000;

/** Au-delà de ce silence, la session se ferme même si sa durée absolue court encore. */
export const SESSION_IDLE_MS = Number(process.env.ZANSHIN_SESSION_IDLE_MINUTES ?? 60) * 60 * 1000;

/** 32 octets d'entropie : 43 caractères en base64url, rien à échapper. */
const TOKEN_BYTES = 32;

export interface Session {
    token: string;
    userId: number;
    username: string;
    role: string;
    /** Millisecondes epoch. */
    createdAt: number;
    lastSeenAt: number;
    /** Le compte doit changer son mot de passe avant d'accéder au reste. */
    mustChangePassword: boolean;
}

export function newSessionToken(): string {
    return randomBytes(TOKEN_BYTES).toString('base64url');
}

export type SessionState = 'active' | 'expired' | 'idle';

/**
 * L'état d'une session à un instant donné.
 *
 * Les deux causes de fermeture sont distinguées parce que l'opérateur qui règle les
 * durées a besoin de savoir laquelle ferme réellement les sessions de ses utilisateurs.
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
 * Compare deux jetons en temps constant.
 *
 * Une comparaison ordinaire s'arrête au premier octet qui diffère, et sa durée renseigne
 * sur le nombre d'octets déjà corrects. Peu exploitable sur un réseau, et fermer la
 * porte ne coûte rien.
 */
export function tokensMatch(candidate: string, expected: string): boolean {
    const a = Buffer.from(candidate);
    const b = Buffer.from(expected);
    // `timingSafeEqual` exige des longueurs égales ; une longueur différente est de
    // toute façon un refus, et la révéler n'apprend rien d'utile.
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

/**
 * Extrait le jeton d'un en-tête `Authorization`.
 *
 * Rend `null` sur tout ce qui n'est pas exactement `Bearer <jeton>` : distinguer
 * « absent », « mal formé » et « inconnu » renseignerait quelqu'un qui sonde, sans aider
 * personne d'autre.
 */
export function bearerToken(header: string | null | undefined): string | null {
    if (!header) return null;
    const match = /^Bearer (\S+)$/.exec(header.trim());
    return match ? match[1] : null;
}
