import { type Dialect, parseDialect } from './dialects';

/**
 * Le dialecte que ce processus sert, lu une fois.
 *
 * **Lu à l'import et non par appel** : les définitions de colonnes sont des constantes de
 * module, évaluées quand TypeORM charge les entités. Un processus ne parle qu'à une base,
 * donc une seule lecture suffit — et la changer en cours de route n'aurait aucun sens.
 */
export const DIALECT: Dialect = parseDialect(process.env.ZANSHIN_DB_DIALECT ?? 'postgres');

export const isMySql = (dialect: Dialect = DIALECT): boolean => dialect === 'mysql' || dialect === 'mariadb';

/**
 * Les orthographes de types, par dialecte.
 *
 * PostgreSQL et MySQL ne nomment pas les mêmes choses pareil, et **TypeORM ne traduit
 * pas** : `timestamp with time zone` ou `double precision` envoyés à MySQL produisent une
 * erreur de syntaxe à la création de la table. Ce module est le seul endroit où ces
 * différences existent.
 *
 * **La précision des horodatages est le point critique.** La chaîne d'intégrité du journal
 * d'audit couvre l'horodatage sérialisé en ISO, donc à la milliseconde. Un `DATETIME` MySQL
 * sans précision tronque à la seconde : chaque entrée échouerait alors à sa propre
 * vérification et **le journal se déclarerait falsifié sans que rien ne l'ait été**. C'est
 * la raison pour laquelle la pile Python avait retiré MySQL. `datetime(6)` supprime la
 * cause — et la précision est déclarée ici, en un seul endroit, plutôt que colonne par
 * colonne où une seule oubliée suffirait à casser la chaîne.
 *
 * `datetime` et non `timestamp` : le `TIMESTAMP` de MySQL s'arrête en 2038 et convertit
 * selon le fuseau de session. La source de données force la connexion en UTC, ce qui rend
 * `datetime` non ambigu tout en évitant la borne de 2038.
 */
export interface ColumnSpelling {
    timestamp: { type: string; precision?: number };
    string: string;
    uuid: string;
    text: string;
    int: string;
    bigint: string;
    bool: string;
    float: string;
    json: string;
}

const POSTGRES: ColumnSpelling = {
    timestamp: { type: 'timestamp with time zone' },
    string: 'character varying',
    uuid: 'uuid',
    text: 'text',
    int: 'integer',
    bigint: 'bigint',
    bool: 'boolean',
    float: 'double precision',
    json: 'json'
};

const MYSQL: ColumnSpelling = {
    // Six chiffres : la chaîne d'audit en a besoin de trois, et la marge ne coûte rien.
    timestamp: { type: 'datetime', precision: 6 },
    string: 'varchar',
    // MySQL n'a pas de type `uuid`. `varchar(36)` porte la forme canonique que
    // `@PrimaryGeneratedColumn('uuid')` produit, et reste compatible avec les clés
    // étrangères qui la référencent.
    uuid: 'varchar',
    text: 'text',
    int: 'int',
    bigint: 'bigint',
    // TypeORM rend `tinyint(1)`, que le pilote relit en booléen.
    bool: 'boolean',
    float: 'double',
    json: 'json'
};

/**
 * SQLite ne connaît que cinq classes de stockage, et déduit la sienne du **nom** du type.
 *
 * Les orthographes ci-dessous sont donc choisies pour tomber dans la bonne classe :
 * `varchar` et `text` en TEXT, `integer` en INTEGER, `real` en REAL. Rien n'est vérifié à
 * l'écriture — SQLite accepte n'importe quelle valeur dans n'importe quelle colonne — ce
 * qui déplace la rigueur vers les entités et les migrations.
 *
 * **`datetime` est du texte, et c'est ce qui sauve la chaîne d'audit.** Le pilote sérialise
 * un `Date` en ISO à la milliseconde, exactement la précision que l'empreinte du journal
 * couvre. C'est le piège qui avait coûté MySQL à la pile Python — un `DATETIME` tronqué à
 * la seconde y faisait échouer chaque entrée à sa propre vérification — et il ne se pose
 * pas ici, à condition de ne jamais laisser TypeORM choisir un entier.
 */
const SQLITE: ColumnSpelling = {
    timestamp: { type: 'datetime' },
    string: 'varchar',
    // Pas de type `uuid` : la forme canonique tient dans du texte, comme sous MySQL.
    uuid: 'varchar',
    text: 'text',
    int: 'integer',
    // SQLite n'a qu'un entier 64 bits ; `bigint` et `integer` y désignent le même stockage.
    bigint: 'bigint',
    bool: 'boolean',
    float: 'real',
    // Stocké en texte. TypeORM sérialise et relit, ce que la colonne `json` attend.
    json: 'json'
};

/**
 * **MariaDB n'est pas MySQL**, et le seul écart tient dans une ligne.
 *
 * Depuis la 10.7 il porte un type `uuid` natif, que son pilote choisit de lui-même pour une
 * clé engendrée. Déclarer `varchar` ici serait donc écrire une chose et en obtenir une
 * autre : TypeORM corrigeait en silence, et le schéma issu des migrations MySQL réclamait
 * aussitôt soixante-deux instructions de reprise — chaque clé primaire comprise.
 *
 * Le type natif est en outre le bon choix : seize octets au lieu de trente-six, et un ordre
 * de tri qui a un sens.
 */
const MARIADB: ColumnSpelling = { ...MYSQL, uuid: 'uuid' };

export const SPELLING: ColumnSpelling =
    DIALECT === 'sqlite' ? SQLITE : DIALECT === 'mariadb' ? MARIADB : isMySql() ? MYSQL : POSTGRES;

/** La longueur d'un UUID en forme canonique, quand le dialecte exige une longueur. */
export const UUID_LENGTH = 36;
