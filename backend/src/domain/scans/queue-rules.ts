/**
 * Les règles de la file de scans — pures, sans requête.
 *
 * La file vit en base et non dans un pool de fils d'exécution. Trois raisons, chacune
 * constatée : un pool rend la file **invisible** (douze scans déclenchés, aucun moyen de
 * savoir lequel tournera quand) ; **un redémarrage la perd** (les lignes survivent, les
 * futures non, et ces scans restent en attente pour toujours) ; et la limite de
 * parallélisme devient une propriété du processus au lieu d'un réglage.
 *
 * L'ordre est celui de création, sans priorité. Une colonne de priorité serait facile à
 * ajouter et manque délibérément : « dans l'ordre où on les a demandés » est une règle
 * qu'un opérateur peut prédire, et la première chose que coûte un schéma de priorité est
 * cette prévisibilité.
 */

/** Durée d'un bail. Au-delà, un scan est considéré abandonné et redevient réclamable. */
export const LEASE_MS = Number(process.env.ZANSHIN_SCAN_LEASE_SECONDS ?? 1200) * 1000;

/**
 * Nombre de reprises avant l'échec définitif.
 *
 * Sans plafond, une cible qui bloque son travailleur à tous les coups circulerait d'un
 * agent à l'autre indéfiniment, consommant la capacité de toute la flotte — et
 * l'opérateur verrait un scan éternellement « sur le point de démarrer ».
 */
export const MAX_ATTEMPTS = Number(process.env.ZANSHIN_SCAN_MAX_ATTEMPTS ?? 3);

/**
 * Tentatives de réclamation avant d'abandonner un tour.
 *
 * **Existe pour MySQL**, qui compte les lignes sautées dans son `LIMIT` : avec
 * `LIMIT 1`, dix réclamants concurrents sur une file de vingt scans en laissaient six
 * les mains vides. Rien n'était jamais réclamé deux fois — c'était un problème de débit,
 * dont la forme en production est un agent qui interroge pendant trente secondes pendant
 * que du travail attend.
 *
 * PostgreSQL ne se comporte pas ainsi : il continue de parcourir jusqu'à obtenir `LIMIT`
 * lignes non verrouillées. La boucle sort dès que la limite est atteinte ou la file vide,
 * donc elle ne coûte rien là où elle ne sert pas.
 */
export const CLAIM_ATTEMPTS = Number(process.env.ZANSHIN_SCAN_CLAIM_ATTEMPTS ?? 12);

export const LEASE_EXHAUSTED_MESSAGE =
    "Le scan a été repris trop de fois sans aboutir : son travailleur cesse de répondre avant la fin. " +
    'Vérifiez les journaux de l’agent, puis relancez le scan.';

/**
 * Combien de scans peuvent encore démarrer.
 *
 * Calculée à chaque distribution plutôt que fixée au démarrage : c'est ce qui rend la
 * limite modifiable sans redémarrer l'application.
 */
export function capacity(maxConcurrent: number, running: number): number {
    return Math.max(0, maxConcurrent - running);
}

/** Un bail qui n'expire jamais n'est pas un bail : l'absence de date vaut expiration. */
export function leaseHasLapsed(leaseExpiresAt: Date | null, asOf: Date): boolean {
    return leaseExpiresAt === null || leaseExpiresAt < asOf;
}

/**
 * Ce qu'il advient d'un scan dont le bail a expiré.
 *
 * Rien n'est *arrêté* ici : le travail tourne peut-être encore ailleurs, et rien dans ce
 * processus ne peut tuer un fil sur une autre machine. La ligne redevient réclamable, et
 * c'est `stillOwned` qui refusera ensuite les résultats du travailleur déchu.
 */
export function afterLapse(attempts: number): 'requeue' | 'fail' {
    return attempts >= MAX_ATTEMPTS ? 'fail' : 'requeue';
}

/** Le bail à poser au moment d'une réclamation. */
export function leaseUntil(claimedAt: Date): Date {
    return new Date(claimedAt.getTime() + LEASE_MS);
}
