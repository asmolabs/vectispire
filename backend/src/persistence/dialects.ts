/**
 * Les bases prises en charge, et ce que chacune sait faire.
 *
 * TypeORM parle à une dizaine de moteurs, mais « le pilote se connecte » et « le
 * système est correct dessus » sont deux affirmations différentes. Ce module porte la
 * seconde, parce que les trois divergences ci-dessous ne produisent **aucune erreur** :
 * elles produisent des données fausses.
 *
 * Chacune a été trouvée en exécutant, pas en lisant, du temps où la pile Python
 * prenait MySQL en charge :
 *
 * 1. **`DATETIME` tronque à la seconde.** La chaîne d'intégrité du journal d'audit
 *    couvre l'horodatage à la microseconde. Sur un moteur qui la tronque, chaque
 *    entrée échoue à sa propre vérification : le journal se déclare falsifié, sans
 *    que rien ne l'ait été. C'est la raison qui avait fait retirer MySQL.
 * 2. **`SKIP LOCKED` compte les lignes sautées dans le `LIMIT`.** La réclamation d'un
 *    scan devient alors partielle sous charge : le lot revient court alors que la
 *    file ne l'est pas, et la concurrence réelle s'effondre en silence.
 * 3. **`NULLS LAST` est une erreur de syntaxe.** Elle apparaît dans les tris du
 *    backlog.
 *
 * Et pour SQLite, une quatrième, d'une autre nature :
 *
 * 4. **SQLAlchemy comme TypeORM *suppriment* silencieusement `FOR UPDATE`.** La
 *    réclamation ressemble alors à une transaction, passe tous les tests sur la
 *    machine d'un développeur, et remet le même scan à deux processus en production.
 *    D'où `CAN_CLAIM_TRANSACTIONALLY`, et le refus au démarrage d'une deuxième
 *    instance sur SQLite.
 *
 * **Le parti pris de ce module : rien n'est interdit, tout est déclaré.** Un opérateur
 * qui choisit MySQL doit l'apprendre au démarrage, dans un message qui nomme la
 * conséquence — pas des mois plus tard, en découvrant un journal d'audit qui s'accuse
 * lui-même.
 */

export const SUPPORTED_DIALECTS = ['postgres', 'sqlite', 'mysql', 'mariadb'] as const;
export type Dialect = (typeof SUPPORTED_DIALECTS)[number];

export interface DialectCapabilities {
    /**
     * `SELECT … FOR UPDATE SKIP LOCKED` fait ce qu'on croit : la réclamation de scans
     * est réellement transactionnelle, donc plusieurs processus peuvent drainer la
     * même file sans se marcher dessus.
     */
    canClaimTransactionally: boolean;
    /**
     * Les horodatages conservent la microseconde. La chaîne d'audit en dépend
     * entièrement.
     */
    preservesMicroseconds: boolean;
    /** `ORDER BY … NULLS LAST` est accepté. */
    supportsNullsLast: boolean;
    /** Plusieurs processus peuvent écrire dans la même base. */
    supportsConcurrentWriters: boolean;
}

export const CAPABILITIES: Record<Dialect, DialectCapabilities> = {
    postgres: {
        canClaimTransactionally: true,
        preservesMicroseconds: true,
        supportsNullsLast: true,
        supportsConcurrentWriters: true
    },
    sqlite: {
        // `FOR UPDATE` est accepté puis ignoré : le pire des deux mondes.
        canClaimTransactionally: false,
        preservesMicroseconds: true,
        supportsNullsLast: true,
        // Un seul écrivain. Deux instances sur un fichier, ce n'est pas lent, c'est
        // corrompu.
        supportsConcurrentWriters: false
    },
    mysql: {
        // `SKIP LOCKED` existe depuis MySQL 8, mais compte les lignes sautées dans
        // le `LIMIT` : la réclamation revient courte sous charge.
        canClaimTransactionally: false,
        // `DATETIME` sans précision tronque à la seconde. `DATETIME(6)` la conserve,
        // ce qui est la parade — mais elle doit être posée sur *chaque* colonne, et
        // une seule oubliée suffit à casser la chaîne d'audit.
        preservesMicroseconds: false,
        supportsNullsLast: false,
        supportsConcurrentWriters: true
    },
    mariadb: {
        canClaimTransactionally: false,
        preservesMicroseconds: false,
        supportsNullsLast: false,
        supportsConcurrentWriters: true
    }
};

export interface DialectWarning {
    capability: keyof DialectCapabilities;
    message: string;
}

/**
 * Ce qu'un opérateur doit savoir avant de servir une requête sur ce moteur.
 *
 * Retourné plutôt que journalisé ici : l'appelant décide s'il avertit, refuse, ou
 * exige un aveu explicite par variable d'environnement.
 */
export function warningsFor(dialect: Dialect): DialectWarning[] {
    const capabilities = CAPABILITIES[dialect];
    const warnings: DialectWarning[] = [];

    if (!capabilities.preservesMicroseconds) {
        warnings.push({
            capability: 'preservesMicroseconds',
            message:
                `${dialect} tronque les horodatages à la seconde (DATETIME sans précision). ` +
                "La chaîne d'intégrité du journal d'audit couvre l'horodatage : chaque entrée " +
                'échouera à sa propre vérification, et le journal se déclarera falsifié alors ' +
                "que rien ne l'aura été. Déclarez DATETIME(6) sur toutes les colonnes de date, " +
                'ou utilisez PostgreSQL.'
        });
    }
    if (!capabilities.canClaimTransactionally) {
        warnings.push({
            capability: 'canClaimTransactionally',
            message:
                `${dialect} ne permet pas une réclamation de scans réellement transactionnelle ` +
                "(FOR UPDATE SKIP LOCKED absent, ignoré, ou comptant les lignes sautées dans le LIMIT). " +
                'La réclamation retombe sur un UPDATE conditionnel : correct pour plusieurs fils ' +
                "d'un même processus, pas pour plusieurs processus."
        });
    }
    if (!capabilities.supportsNullsLast) {
        warnings.push({
            capability: 'supportsNullsLast',
            message: `${dialect} refuse « ORDER BY … NULLS LAST » ; les tris du backlog doivent l'émuler par une expression CASE.`
        });
    }
    if (!capabilities.supportsConcurrentWriters) {
        warnings.push({
            capability: 'supportsConcurrentWriters',
            message:
                `${dialect} n'accepte qu'un seul écrivain. Une deuxième instance sur la même base ` +
                'ne serait pas lente, elle corromprait les données. Un fichier, un processus.'
        });
    }
    return warnings;
}

/** Normalise ce qu'un opérateur peut avoir écrit dans la configuration. */
export function parseDialect(value: string): Dialect {
    const normalized = value.trim().toLowerCase();
    const aliases: Record<string, Dialect> = {
        postgres: 'postgres',
        postgresql: 'postgres',
        pg: 'postgres',
        sqlite: 'sqlite',
        sqlite3: 'sqlite',
        mysql: 'mysql',
        mariadb: 'mariadb'
    };
    const dialect = aliases[normalized];
    if (!dialect) {
        throw new Error(`Dialecte « ${value} » non pris en charge. Attendu : ${SUPPORTED_DIALECTS.join(', ')}.`);
    }
    return dialect;
}
