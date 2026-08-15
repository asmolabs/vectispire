import { EntityManager, LessThan, MoreThanOrEqual } from 'typeorm';
import { LoginAttempt, Session } from '../persistence/entities';

/**
 * Accès aux sessions. Aucune règle métier : la durée de vie et l'état d'une session se
 * décident dans `domain/auth/session.ts`.
 */
export class SessionRepository {
    async findByToken(manager: EntityManager, token: string): Promise<Session | null> {
        return manager.findOneBy(Session, { token });
    }

    async save(manager: EntityManager, session: Session): Promise<Session> {
        return manager.save(Session, session);
    }

    /** Révoquer une session : un `DELETE`, et la déconnexion est réelle. */
    async deleteByToken(manager: EntityManager, token: string): Promise<void> {
        await manager.delete(Session, { token });
    }

    /** Fermer toutes les sessions d'un compte — après un changement de mot de passe,
     *  ou parce qu'un administrateur le décide. */
    async deleteByUser(manager: EntityManager, userId: number): Promise<number> {
        const result = await manager.delete(Session, { userId });
        return result.affected ?? 0;
    }

    async findByUser(manager: EntityManager, userId: number): Promise<Session[]> {
        return manager.findBy(Session, { userId });
    }

    /**
     * Purge des sessions périmées, appelée par l'ordonnanceur.
     *
     * Une session expirée est déjà refusée à la lecture ; la purge n'est pas un
     * contrôle de sécurité, seulement de l'hygiène de table.
     */
    async deleteExpired(manager: EntityManager, asOf: Date): Promise<number> {
        const result = await manager.delete(Session, { expiresAt: LessThan(asOf) });
        return result.affected ?? 0;
    }
}

/**
 * Accès aux tentatives de connexion.
 *
 * Une ligne par échec, et un comptage sur fenêtre glissante — pas un compteur avec date
 * de réinitialisation, qui offrirait un pic gratuit au changement de fenêtre.
 */
export class LoginAttemptRepository {
    /**
     * Les instants des échecs encore dans la fenêtre, pour une clé.
     *
     * **Par l'entité et non par `getRawMany`.** Une lecture brute court-circuite
     * l'hydratation, si bien que la valeur rendue est celle du pilote : un `Date` sous
     * PostgreSQL et MySQL, une **chaîne** sous SQLite. L'annotation `Promise<Date[]>` était
     * alors un mensonge que le compilateur ne pouvait pas contredire, et l'appelant tombait
     * sur « `at.getTime` is not a function » — au milieu du chemin de connexion, c'est-à-dire
     * au pire endroit.
     *
     * Même défaut, même correctif que le journal d'audit : laisser l'ORM hydrater, et la
     * portabilité vient avec.
     */
    async since(manager: EntityManager, counterKey: string, since: Date): Promise<Date[]> {
        const rows = await manager.find(LoginAttempt, {
            where: { counterKey, occurredAt: MoreThanOrEqual(since) },
            select: { occurredAt: true }
        });
        return rows.map((row) => row.occurredAt);
    }

    async record(manager: EntityManager, attempt: LoginAttempt): Promise<void> {
        await manager.save(LoginAttempt, attempt);
    }

    /** Efface les compteurs d'une clé — appelé sur une connexion réussie. */
    async clear(manager: EntityManager, counterKey: string): Promise<void> {
        await manager.delete(LoginAttempt, { counterKey });
    }

    /**
     * Efface les tentatives antérieures à la coupure.
     *
     * **Un `Date`, jamais une chaîne bâtie à la main.** La coupure était un ISO composé
     * caractère par caractère, sans fuseau — et la comparaison devenait alors lexicographique
     * contre ce que le moteur avait stocké. PostgreSQL et MySQL rendent
     * `2026-08-15T10:00:00.000Z`, SQLite `2026-08-15 10:00:00.000` : l'espace vaut moins que
     * le « T », donc **toutes** les lignes passaient pour antérieures à la coupure et la
     * purge vidait la table entière.
     *
     * Ce n'était pas un défaut cosmétique : cette table porte les compteurs d'anti-force-brute,
     * et les effacer à chaque passage d'entretien rouvre la fenêtre à qui essaie des mots de
     * passe — exactement ce que la rétention doublée, un peu plus haut, existe pour éviter.
     */
    async deleteBefore(manager: EntityManager, cutoff: Date): Promise<number> {
        const result = await manager.delete(LoginAttempt, { occurredAt: LessThan(cutoff) });
        return result.affected ?? 0;
    }
}
