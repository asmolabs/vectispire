import { EntityManager, LessThan } from 'typeorm';
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
    /** Les instants des échecs encore dans la fenêtre, pour une clé. */
    async since(manager: EntityManager, counterKey: string, since: Date): Promise<Date[]> {
        const rows = await manager
            .createQueryBuilder(LoginAttempt, 'attempt')
            .select('attempt.occurred_at', 'occurredAt')
            .where('attempt.counter_key = :counterKey', { counterKey })
            .andWhere('attempt.occurred_at >= :since', { since })
            .getRawMany<{ occurredAt: Date }>();
        return rows.map((row) => row.occurredAt);
    }

    async record(manager: EntityManager, attempt: LoginAttempt): Promise<void> {
        await manager.save(LoginAttempt, attempt);
    }

    /** Efface les compteurs d'une clé — appelé sur une connexion réussie. */
    async clear(manager: EntityManager, counterKey: string): Promise<void> {
        await manager.delete(LoginAttempt, { counterKey });
    }

    async deleteBefore(manager: EntityManager, cutoff: string): Promise<number> {
        const result = await manager.delete(LoginAttempt, { occurredAt: LessThan(cutoff) });
        return result.affected ?? 0;
    }
}
