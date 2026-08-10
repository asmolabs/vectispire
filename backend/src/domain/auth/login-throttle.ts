/**
 * Limitation des tentatives de connexion.
 *
 * **Deux compteurs indépendants, et les deux doivent passer.** Ce n'est pas une
 * redondance : chacun seul a une faille que l'autre ferme.
 *
 * - Ne compter que par **utilisateur**, et n'importe qui verrouille le compte d'un
 *   collègue dont il connaît l'identifiant — un déni de service à un tiers du coût
 *   d'une attaque.
 * - Ne compter que par **client**, et un attaquant réparti sur plusieurs machines
 *   essaie autant de mots de passe qu'il veut sur un même compte.
 *
 * D'où deux seuils différents : cinq tentatives pour un utilisateur, vingt pour un
 * client. Un poste partagé peut légitimement voir plusieurs personnes se tromper ; un
 * compte, non.
 *
 * **La fenêtre est glissante et non fixe.** Une fenêtre fixe se réinitialise à heure
 * ronde, ce qui offre à un attaquant un pic gratuit au changement de fenêtre.
 *
 * La vérification a lieu **avant** toute comparaison de mot de passe : un compte
 * verrouillé ne doit coûter aucun tour de bcrypt, sans quoi le limiteur devient
 * lui-même le levier d'un déni de service.
 */

export const MAX_ATTEMPTS_PER_USER = 5;
export const MAX_ATTEMPTS_PER_CLIENT = 20;
/** 15 minutes, en millisecondes. */
export const WINDOW_MS = 15 * 60 * 1000;

export interface ThrottleDecision {
    allowed: boolean;
    /** Secondes à attendre avant une nouvelle tentative ; 0 quand c'est autorisé. */
    retryAfterSeconds: number;
}

export interface AttemptCounts {
    /** Les instants (en millisecondes epoch) des échecs de cet utilisateur dans la fenêtre. */
    user: number[];
    /** Idem pour ce client. */
    client: number[];
}

/**
 * L'identifiant sous lequel compter les échecs d'un utilisateur.
 *
 * Normalisé, sinon « Alice », « alice » et « alice  » seraient trois compteurs et le
 * seuil vaudrait trois fois plus pour qui prend la peine de varier la casse.
 */
export function userKey(username: string): string {
    return `login:user:${username.trim().toLowerCase()}`;
}

export function clientKey(clientId: string): string {
    return `login:client:${clientId}`;
}

/**
 * Décide si une tentative est permise, et sinon pour combien de temps encore.
 *
 * Le délai est calculé depuis l'échec **le plus ancien encore dans la fenêtre** : c'est
 * l'instant où le compteur redescendra sous le seuil.
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
    // Arrondi au supérieur : annoncer « 0 seconde » alors qu'il en reste une fraction
    // ferait retenter aussitôt et échouer à nouveau.
    return Math.max(1, Math.ceil((earliest + WINDOW_MS - now) / 1000));
}

/** Ne garde que les tentatives encore dans la fenêtre. */
export function withinWindow(attempts: number[], now: number): number[] {
    return attempts.filter((at) => now - at < WINDOW_MS);
}
