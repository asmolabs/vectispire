/**
 * La politique de reprise de l'outbox.
 *
 * Recul exponentiel, plafonné, puis abandon. Chaque terme de cette phrase est une
 * décision :
 *
 * - **Recul**, parce que les deux pannes réalistes sont un webhook brièvement injoignable
 *   et un webhook mal configuré. Reprendre vite le premier est juste ; reprendre le second
 *   toutes les soixante secondes indéfiniment transforme une erreur de saisie en charge
 *   permanente.
 * - **Tentatives plafonnées**, parce qu'un point de terminaison qui a refusé huit fois en
 *   plusieurs heures n'acceptera pas la neuvième, et qu'une file qui ne se vide jamais
 *   cache derrière ces messages ceux qui pourraient encore partir.
 * - **Abandonné, pas supprimé.** Un message que personne ne recevra jamais est exactement
 *   ce qu'un opérateur doit pouvoir retrouver : il reste, avec sa dernière erreur.
 */

/** Huit tentatives sur une fenêtre qui s'élargit : environ quatre heures au total. */
export const MAX_ATTEMPTS = 8;
export const BASE_BACKOFF_SECONDS = 60;
export const MAX_BACKOFF_SECONDS = 3600;

/**
 * Combien de messages part un passage.
 *
 * L'entretien fait aussi d'autres travaux ; une rafale de deux cents webhooks les
 * affamerait tous.
 */
export const MAX_PER_PASS = 20;

/** Les messages livrés sont gardés quelques jours, pour que « est-ce parti ? » ait une réponse. */
export const SENT_RETENTION_DAYS = 7;

/**
 * `60, 120, 240, …` plafonné à une heure.
 *
 * Calculé depuis le nombre de tentatives plutôt que stocké, pour que la politique puisse
 * changer sans migration et sans que des lignes portent un calendrier d'une version
 * antérieure.
 */
export function backoffSeconds(attempts: number): number {
    if (attempts <= 0) return BASE_BACKOFF_SECONDS;
    return Math.min(BASE_BACKOFF_SECONDS * 2 ** (attempts - 1), MAX_BACKOFF_SECONDS);
}

/** L'erreur telle qu'elle sera conservée : tronquée. */
export function recordableError(error: unknown): string {
    const value = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    // Tronquée : la page d'erreur HTML d'un proxy ne vaut pas un kilooctet par tentative
    // dans une table écrite à chaque scan.
    return value.slice(0, 500);
}

/** L'issue d'une tentative ratée : abandon, ou nouvelle chance à telle date. */
export function nextAttempt(attempts: number, now: Date): { abandoned: boolean; nextAttemptAt: Date | null } {
    if (attempts >= MAX_ATTEMPTS) return { abandoned: true, nextAttemptAt: null };
    return { abandoned: false, nextAttemptAt: new Date(now.getTime() + backoffSeconds(attempts) * 1000) };
}
