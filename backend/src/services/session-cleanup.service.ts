import { EntityManager } from 'typeorm';
import { WINDOW_MS } from '../domain/auth/login-throttle';
import { SESSION_TTL_MS } from '../domain/auth/session';
import { now } from '../domain/common/timestamp';
import { LoginAttemptRepository, SessionRepository } from '../repositories/session.repository';

/**
 * La purge des deux tables d'authentification.
 *
 * **Ce n'est pas un contrôle de sécurité, et c'est important de le dire.** Une session
 * périmée est déjà refusée à la lecture, et une tentative sortie de la fenêtre n'est
 * déjà plus comptée. Cette passe ne rend rien plus sûr : elle empêche seulement deux
 * tables d'accumuler indéfiniment des lignes que personne ne lira jamais.
 *
 * La conséquence pratique : elle peut échouer, sauter un tour, ou ne pas tourner du
 * tout sans que rien de grave n'arrive. C'est exactement pourquoi elle n'a pas le droit
 * de faire échouer le tick de l'ordonnanceur qui l'appelle.
 *
 * Les tentatives sont gardées **deux fois** la fenêtre plutôt qu'exactement une : une
 * purge qui coupe au ras du seuil retirerait des lignes qu'un comptage en cours est
 * peut-être en train de lire, et le seul effet serait d'abaisser un compteur au mauvais
 * moment — c'est-à-dire d'ouvrir une fenêtre à qui essaie des mots de passe.
 */
const ATTEMPT_RETENTION_MS = 2 * WINDOW_MS;

export interface CleanupResult {
    sessions: number;
    attempts: number;
}

export class SessionCleanupService {
    constructor(
        private readonly sessions = new SessionRepository(),
        private readonly attempts = new LoginAttemptRepository()
    ) {}

    /** Ne lève jamais : voir la note de classe. */
    async prune(manager: EntityManager): Promise<CleanupResult> {
        const result: CleanupResult = { sessions: 0, attempts: 0 };
        try {
            result.sessions = await this.sessions.deleteExpired(manager, now());
        } catch {
            // Rien à faire : la prochaine passe reprendra.
        }
        try {
            result.attempts = await this.attempts.deleteBefore(manager, new Date(Date.now() - ATTEMPT_RETENTION_MS));
        } catch {
            // Idem.
        }
        return result;
    }
}

/** Combien de temps une session peut au maximum rester à purger. */
export const MAX_SESSION_AGE_MS = SESSION_TTL_MS;
