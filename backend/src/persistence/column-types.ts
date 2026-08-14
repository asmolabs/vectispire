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

export const SPELLING: ColumnSpelling = isMySql() ? MYSQL : POSTGRES;

/** La longueur d'un UUID en forme canonique, quand le dialecte exige une longueur. */
export const UUID_LENGTH = 36;
