import { types } from 'pg';

/**
 * Correction du décodage des horodatages par `node-postgres`.
 *
 * **À appeler avant d'ouvrir la moindre connexion.** Sans cela, deux défauts se
 * cumulent, aucun des deux ne produisant d'erreur.
 *
 * Mesuré contre un PostgreSQL 16 réel, sur une machine réglée en UTC+2 :
 *
 * | en base                      | par défaut (`Date`)        | avec ce correctif            |
 * |------------------------------|----------------------------|------------------------------|
 * | `2026-08-10 08:13:58.322451` | `2026-08-10T06:13:58.322Z` | `2026-08-10 08:13:58.322451` |
 * | `2026-08-10 08:13:58`        | `2026-08-10T06:13:58.000Z` | `2026-08-10 08:13:58`        |
 * | `2026-01-02 03:04:05.123000` | `2026-01-02T02:04:05.123Z` | `2026-01-02 03:04:05.123`    |
 *
 * 1. **La microseconde est perdue.** `Date` a la milliseconde pour résolution :
 *    `.322451` revient `.322`. L'empreinte du journal d'audit couvre l'horodatage,
 *    donc chaque entrée écrite par l'implémentation Python échouerait à sa propre
 *    vérification — le journal s'accuserait lui-même d'avoir été falsifié. C'est
 *    exactement le mode de panne qui avait fait retirer MySQL, dont le `DATETIME`
 *    tronquait à la seconde.
 * 2. **Le fuseau de la machine est appliqué.** La colonne est un `timestamp without
 *    time zone` contenant de l'UTC — `zanshin/clock.py` le garantit à l'écriture —
 *    mais `node-postgres` l'interprète comme une heure *locale* et convertit. Deux
 *    heures d'écart ici, zéro sur un serveur en UTC : le genre de défaut qui traverse
 *    tous les tests et n'apparaît qu'en production, décalant chaque date affichée et
 *    chaque fenêtre de bail.
 *
 * Le correctif est de ne rien décoder du tout : le texte de PostgreSQL passe tel quel,
 * et `domain/common/timestamp.ts` le décompose et le canonicalise. Rendre une chaîne plutôt qu'un `Date` est un choix : le type
 * riche est précisément celui qui perd de l'information ici.
 *
 * Attention au rendu : PostgreSQL **retire les zéros de queue** de la fraction. 123 000
 * microsecondes reviennent en `.123`, et 10 microsecondes en `.00001`. Lire cette
 * fraction comme un entier la décalerait d'un facteur mille ; `parsePythonTimestamp`
 * la complète à droite, ce que ses tests vérifient.
 */

/** `timestamp without time zone` — le type de toutes les colonnes de date de Zanshin. */
const OID_TIMESTAMP = 1114;

/** `timestamp with time zone`. Aucune colonne n'en utilise, mais un `now()` non
 *  qualifié dans une requête écrite à la main en renvoie un ; le laisser en texte
 *  évite qu'il se comporte différemment de tous les autres. */
const OID_TIMESTAMPTZ = 1184;

/** `date`. Même raisonnement : pas de conversion implicite de fuseau. */
const OID_DATE = 1082;

const identity = (value: string): string => value;

let applied = false;

/**
 * Idempotent : les parseurs de `pg` sont un registre global au processus, et
 * l'appeler depuis plusieurs modules ne doit pas coûter davantage qu'un appel.
 */
export function configurePostgresTypeParsers(): void {
    if (applied) return;
    for (const oid of [OID_TIMESTAMP, OID_TIMESTAMPTZ, OID_DATE]) {
        types.setTypeParser(oid, identity);
    }
    applied = true;
}

/** Pour les tests, qui ont besoin d'observer l'état par défaut puis l'état corrigé. */
export function resetPostgresTypeParsersForTesting(): void {
    applied = false;
}

export const TIMESTAMP_TYPE_OIDS = Object.freeze({
    timestamp: OID_TIMESTAMP,
    timestamptz: OID_TIMESTAMPTZ,
    date: OID_DATE
});
