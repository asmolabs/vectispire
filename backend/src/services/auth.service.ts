import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';
import { SESSION_TTL_MS, Session as SessionRules, bearerToken, isActive, newSessionToken, stateOf } from '../domain/auth/session';
import { MAX_ATTEMPTS_PER_CLIENT, MAX_ATTEMPTS_PER_USER, WINDOW_MS, clientKey, decide, userKey } from '../domain/auth/login-throttle';
import { nowForDatabase } from '../domain/common/timestamp';
import { AuditOperation, LoginAttempt, Session, User } from '../persistence/entities';
import { LoginAttemptRepository, SessionRepository } from '../repositories/session.repository';
import { verifyPassword } from './password.service';

/**
 * L'assemblage de l'authentification : limiteur, vérification, session.
 *
 * L'ordre des trois n'est pas indifférent. **Le limiteur passe avant toute comparaison
 * de mot de passe** : un compte verrouillé ne doit coûter aucun tour de bcrypt, sans
 * quoi le limiteur devient lui-même le levier d'un déni de service — chaque tentative
 * refusée consommerait plus de CPU qu'elle n'en fait économiser.
 *
 * Les trois issues sont auditées — succès, échec, blocage — parce qu'un journal qui ne
 * consigne que les échecs ne permet pas de distinguer « quelqu'un s'est trompé deux
 * fois » de « quelqu'un parcourt la liste des comptes depuis un hôte ».
 */

export type LoginOutcome =
    | { kind: 'success'; session: Session; user: User }
    | { kind: 'invalid' }
    | { kind: 'blocked'; retryAfterSeconds: number };

export interface LoginRequest {
    username: string;
    password: string;
    /** Identifie le client, pour le second compteur. Jamais une adresse IP seule :
     *  derrière un NAT d'entreprise, tout le monde partagerait le même verrou. */
    clientId: string;
    userAgent?: string | null;
    ipAddress?: string | null;
}

/** Ce que l'appelant doit journaliser. Rendu plutôt qu'écrit ici, pour que le service
 *  ne dépende pas du journal d'audit et reste testable seul. */
export interface AuditIntent {
    operationType: string;
    resourceId: string;
    description: string;
    userId: string | null;
}

export class AuthService {
    constructor(
        private readonly sessions = new SessionRepository(),
        private readonly attempts = new LoginAttemptRepository()
    ) {}

    async login(manager: EntityManager, request: LoginRequest): Promise<{ outcome: LoginOutcome; audit: AuditIntent }> {
        const now = Date.now();
        const since = isoMillisAgo(now, WINDOW_MS);
        const keys = { user: userKey(request.username), client: clientKey(request.clientId) };

        const counts = {
            user: (await this.attempts.since(manager, keys.user, since)).map(toEpochMillis),
            client: (await this.attempts.since(manager, keys.client, since)).map(toEpochMillis)
        };

        const throttle = decide(counts, now);
        if (!throttle.allowed) {
            // Refusé avant tout bcrypt : c'est le point de la vérification préalable.
            return {
                outcome: { kind: 'blocked', retryAfterSeconds: throttle.retryAfterSeconds },
                audit: {
                    operationType: AuditOperation.LOGIN_BLOCKED,
                    resourceId: request.username,
                    description: `Tentative refusée par le limiteur (${throttle.retryAfterSeconds} s à attendre)`,
                    userId: request.username
                }
            };
        }

        const user = await manager.findOneBy(User, { username: request.username });
        // `verifyPassword` est appelé même sans utilisateur trouvé ? Non : ce serait un
        // bcrypt gratuit à chaque identifiant inconnu, donc un levier de déni de
        // service. La différence de temps entre « compte inconnu » et « mot de passe
        // faux » est réelle, et c'est le limiteur qui la rend inexploitable.
        const authenticated = user !== null && user.isActive && verifyPassword(request.password, user.password);

        if (!authenticated) {
            await this.recordFailure(manager, keys.user);
            await this.recordFailure(manager, keys.client);
            return {
                outcome: { kind: 'invalid' },
                audit: {
                    operationType: AuditOperation.LOGIN_FAILURE,
                    resourceId: request.username,
                    // Volontairement sans préciser si le compte existe : le journal est
                    // lu par des humains, mais une réponse trop précise finit par
                    // fuiter dans un message d'erreur.
                    description: 'Échec de connexion',
                    userId: request.username
                }
            };
        }

        await this.attempts.clear(manager, keys.user);
        await this.attempts.clear(manager, keys.client);

        const session = await this.openSession(manager, user, request);
        return {
            outcome: { kind: 'success', session, user },
            audit: {
                operationType: AuditOperation.LOGIN_SUCCESS,
                resourceId: user.username,
                description: 'Connexion réussie',
                userId: user.username
            }
        };
    }

    /**
     * Résout un jeton en session active, et rafraîchit son horodatage d'activité.
     *
     * Une session périmée est **supprimée** au lieu d'être seulement refusée : la
     * laisser en base ferait grossir la table de lignes qui ne serviront plus, et la
     * purge de l'ordonnanceur n'aurait plus qu'à ramasser ce que personne n'a touché.
     */
    async resolve(manager: EntityManager, authorization: string | null | undefined): Promise<Session | null> {
        const token = bearerToken(authorization);
        if (!token) return null;

        const session = await this.sessions.findByToken(manager, token);
        if (!session) return null;

        const rules = { createdAt: toEpochMillis(session.createdAt), lastSeenAt: toEpochMillis(session.lastSeenAt) };
        if (!isActive(rules, Date.now())) {
            await this.sessions.deleteByToken(manager, token);
            return null;
        }

        session.lastSeenAt = nowForDatabase();
        return this.sessions.save(manager, session);
    }

    /** Déconnexion réelle : la ligne disparaît, le jeton ne vaut plus rien. */
    async revoke(manager: EntityManager, token: string): Promise<void> {
        await this.sessions.deleteByToken(manager, token);
    }

    /**
     * Ferme toutes les sessions d'un compte.
     *
     * Appelé après un changement de mot de passe : garder ouvertes les sessions d'un
     * mot de passe qu'on vient de remplacer viderait le geste de son sens.
     */
    async revokeAllForUser(manager: EntityManager, userId: number): Promise<number> {
        return this.sessions.deleteByUser(manager, userId);
    }

    private async openSession(manager: EntityManager, user: User, request: LoginRequest): Promise<Session> {
        const now = nowForDatabase();
        const session = new Session();
        session.token = newSessionToken();
        session.userId = user.id;
        session.createdAt = now;
        session.lastSeenAt = now;
        session.expiresAt = isoMillisAgo(Date.now(), -SESSION_TTL_MS);
        session.userAgent = request.userAgent?.slice(0, 255) ?? null;
        session.ipAddress = request.ipAddress ?? null;
        return this.sessions.save(manager, session);
    }

    private async recordFailure(manager: EntityManager, counterKey: string): Promise<void> {
        const attempt = new LoginAttempt();
        attempt.id = randomUUID();
        attempt.counterKey = counterKey;
        attempt.occurredAt = nowForDatabase();
        await this.attempts.record(manager, attempt);
    }
}

/** Les seuils, réexportés pour que l'API puisse les annoncer sans connaître le domaine. */
export const THROTTLE_LIMITS = Object.freeze({ perUser: MAX_ATTEMPTS_PER_USER, perClient: MAX_ATTEMPTS_PER_CLIENT, windowMs: WINDOW_MS });

/**
 * Un horodatage de session en millisecondes epoch.
 *
 * **Accepte une chaîne ou un `Date`, et c'est une concession mesurée.** Le parseur de
 * `pg` rend bien du texte (`persistence/pg-types.ts` le vérifie contre un vrai
 * serveur), mais **TypeORM ré-hydrate les colonnes de date pour son compte** avant de
 * remplir une entité : ce qui arrive ici est un `Date`, pas la chaîne d'origine.
 *
 * Pour les sessions, c'est sans conséquence : leurs durées se comparent à la seconde,
 * et la milliseconde que `Date` conserve suffit largement.
 *
 * **Ce ne l'est pas pour la chaîne d'intégrité du journal d'audit**, dont l'empreinte
 * couvre l'horodatage. Ce chemin-là lira ses lignes en SQL brut plutôt qu'à travers une
 * entité — c'est la seule façon de garder la valeur exacte que la base contient.
 */
function toEpochMillis(timestamp: string | Date): number {
    if (timestamp instanceof Date) {
        // TypeORM a construit ce `Date` en interprétant un texte **naïf** comme une
        // heure *locale*. Relire ses composantes locales restitue donc exactement les
        // chiffres que la base contient, et les traiter comme de l'UTC annule le
        // décalage. Sans cette inversion, une session naissait deux heures dans le
        // passé sur une machine en UTC+2 et se fermait aussitôt pour inactivité — et
        // zéro écart sur un serveur en UTC, donc invisible en CI.
        return Date.UTC(
            timestamp.getFullYear(),
            timestamp.getMonth(),
            timestamp.getDate(),
            timestamp.getHours(),
            timestamp.getMinutes(),
            timestamp.getSeconds(),
            timestamp.getMilliseconds()
        );
    }
    // Suffixe `Z` explicite : la colonne est sans fuseau et contient de l'UTC, et sans
    // lui `Date` l'interpréterait comme une heure locale.
    return Date.parse(`${timestamp.replace(' ', 'T')}Z`);
}

function isoMillisAgo(now: number, ago: number): string {
    const at = new Date(now - ago);
    const pad = (value: number, width = 2) => String(value).padStart(width, '0');
    return (
        `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}` +
        `T${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}:${pad(at.getUTCSeconds())}.${pad(at.getUTCMilliseconds(), 3)}`
    );
}

export { stateOf as sessionStateOf };
export type { SessionRules };
