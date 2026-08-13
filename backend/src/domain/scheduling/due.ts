import { CronTime } from 'cron';

/**
 * Quand une cible doit être rescannée.
 *
 * `scanIntervalMinutes`, `scanCron` et `lastScheduledScanAt` existent sur les dépôts et les
 * conteneurs depuis le début, et l'écran collecte un intervalle pour chaque cible ajoutée.
 * **Rien ne les lisait**, donc chaque scan était manuel — dans un outil dont la prémisse
 * entière est que *de nouvelles vulnérabilités apparaissent dans du code inchangé*. Un scan
 * manuel hebdomadaire n'est pas de la gestion de posture.
 *
 * **L'expression cron l'emporte sur l'intervalle.** Elle est la plus spécifique des deux, et
 * un intervalle ne sait pas dire « toutes les nuits à deux heures » : il dérive un peu à
 * chaque tour, parce que le prochain se compte depuis le dernier, si bien qu'un scan réglé
 * pour les heures creuses finit par tourner en pleine journée. Pour un travail qui démarre
 * des conteneurs et tire des registres entiers, l'heure n'est pas un détail. Effacer
 * l'expression ramène la cible à son intervalle.
 *
 * Fonctions pures : la politique se teste sans base ni horloge réelle.
 */

/** L'expression n'est pas quelque chose sur quoi on peut ordonnancer. */
export class InvalidCronExpression extends Error {}

/**
 * Normalise une expression, ou lève avec un message sur lequel un opérateur peut agir.
 *
 * Appelée à l'enregistrement d'une cible, pour la même raison que la validation d'URL :
 * **le point d'entrée est là où une erreur coûte peu à corriger**. Découvrir qu'une
 * expression a été rejetée en regardant des scans *ne pas* se produire est la manière
 * chère.
 *
 * Vide veut dire « pas de cron », qui est un état valide : c'est ainsi qu'un opérateur
 * revient à l'ordonnancement par intervalle.
 */
export function validateExpression(expression: string | null | undefined): string | null {
    const value = (expression ?? '').trim();
    if (!value) return null;

    try {
        new CronTime(value);
    } catch {
        throw new InvalidCronExpression(
            `Expression cron invalide : « ${value} ». Format attendu : minute heure jour mois jour-de-semaine — ` +
                'par exemple « 0 2 * * * » (toutes les nuits à 2 h) ou « 0 3 * * 1 » (tous les lundis à 3 h).'
        );
    }
    return value;
}

/**
 * L'intervalle d'une cible s'est-il écoulé ?
 *
 * Une cible sans intervalle n'est jamais ordonnancée (manuelle seulement). Une cible jamais
 * scannée automatiquement est **due immédiatement** — sinon activer l'ordonnanceur la
 * laisserait attendre un intervalle entier avant son premier tour, soit une journée de
 * silence avec le défaut de 1440 minutes.
 */
export function intervalDue(intervalMinutes: number | null, lastScheduledAt: Date | null, now: Date): boolean {
    if (!intervalMinutes || intervalMinutes <= 0) return false;
    if (lastScheduledAt === null) return true;
    return now.getTime() - lastScheduledAt.getTime() >= intervalMinutes * 60_000;
}

/**
 * Une occurrence est-elle passée depuis le dernier tour ordonnancé ?
 *
 * **Calculée depuis `lastScheduledAt` et non depuis `now`** : un tour qui s'exécute en
 * retard — un redémarrage, une passe lente — rattrape ainsi l'occurrence qu'il a manquée au
 * lieu de sauter à la suivante.
 */
export function cronDue(expression: string, lastScheduledAt: Date | null, now: Date): boolean {
    if (!expression) return false;

    let time: CronTime;
    try {
        time = new CronTime(expression);
    } catch {
        // Vérifié **avant** le raccourci « jamais ordonnancée », et cet ordre compte : une
        // expression inutilisable partirait sinon une fois — le seul envoi que personne
        // n'a demandé, venant de la seule cible dont la configuration est cassée.
        return false;
    }

    if (lastScheduledAt === null) return true;

    return time.getNextDateFrom(lastScheduledAt).toJSDate() <= now;
}

/** Ce dont l'échéance a besoin. Volontairement plus étroit que les entités. */
export interface Schedulable {
    scanCron: string | null;
    scanIntervalMinutes: number | null;
    lastScheduledScanAt: Date | null;
}

/** Cette cible est-elle due, selon l'horaire qu'elle porte ? */
export function isTargetDue(target: Schedulable, now: Date): boolean {
    if (target.scanCron) return cronDue(target.scanCron, target.lastScheduledScanAt, now);
    return intervalDue(target.scanIntervalMinutes, target.lastScheduledScanAt, now);
}
