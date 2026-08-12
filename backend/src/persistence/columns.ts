import { ColumnOptions } from 'typeorm';

/**
 * Types de colonnes partagés, pour que chaque entité les déclare de la même façon.
 *
 * **Le schéma appartient à Alembic, pas à TypeORM.** Tant que les deux plans de
 * contrôle coexistent, les quinze révisions Alembic restent l'unique source du schéma
 * et TypeORM tourne en `synchronize: false`. Ces entités *décrivent* des tables
 * existantes ; elles ne les créent pas. `database/schema-parity.integration-spec.ts`
 * est ce qui vérifie que la description reste exacte — l'équivalent d'`alembic check`.
 *
 * Les clés primaires n'utilisent pas ces helpers : `@PrimaryColumn` exige
 * `nullable?: false`, que `ColumnOptions` ne garantit pas. Elles déclarent donc leur
 * type en clair, ce qui reste lisible pour les deux seules qui existent.
 */

/**
 * Un horodatage, lu et écrit en **texte**.
 *
 * Aucun `transformer`, délibérément : convertir en `Date` perdrait la microseconde et
 * appliquerait le fuseau de la machine (voir `pg-types.ts`). Les valeurs circulent
 * donc au format `datetime.isoformat()` de Python, qui est celui qui entre dans la
 * chaîne d'intégrité du journal d'audit.
 */
/**
 * Un instant, avec son fuseau.
 *
 * C'était `timestamp without time zone`, reproduit du schéma SQLAlchemy. Ce choix a
 * produit cinq défauts distincts dans ce portage : node-postgres rendait un `Date`
 * interprété dans le fuseau de la machine, TypeORM réhydratait les colonnes que l'entité
 * déclarait en texte, et une session naissait deux heures dans le passé l'été. Chacun
 * demandait un contournement — `pg-types.ts`, `asTimestampText()`, la canonicalisation
 * dans l'empreinte d'audit — et chacun s'est fait oublier au moins une fois.
 *
 * `timestamptz` supprime la cause : PostgreSQL stocke un instant absolu, le pilote rend
 * un `Date`, et il n'y a plus rien à convertir ni à canonicaliser.
 */
export const timestampColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'timestamp with time zone',
    ...options
});

/** `String(255)` du modèle SQLAlchemy — la longueur par défaut de tout ce schéma. */
export const stringColumn = (length = 255, options: ColumnOptions = {}): ColumnOptions => ({
    type: 'character varying',
    length,
    ...options
});

/**
 * L'identifiant binaire des tables qui n'ont pas de clé entière.
 *
 * `GUID` côté Python : `uuid` natif sur PostgreSQL, `BINARY(16)` ailleurs. Le type
 * maison existait parce que `impl = BINARY` produisait un DDL que PostgreSQL refuse
 * (« type "binary" does not exist ») dès la première table de la première migration ;
 * avec PostgreSQL seul, c'est un `uuid` ordinaire.
 */
/**
 * Une clé étrangère vers une table à clé UUID.
 *
 * `uuid` et non `char(36)` : TypeORM traduit ce type selon le dialecte — `uuid` natif en
 * PostgreSQL, `varchar(36)` en MySQL qui n'en a pas. Écrire `char(36)` à la main donnerait
 * un type incompatible avec la clé primaire référencée, que
 * `@PrimaryGeneratedColumn('uuid')` laisse justement TypeORM choisir.
 */
export const uuidColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'uuid',
    ...options
});

/** `Text` du modèle SQLAlchemy : sans longueur, pour ce qu'on ne veut pas tronquer. */
export const textColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'text',
    ...options
});

export const intColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'integer',
    ...options
});

/**
 * `BigInteger`. Une seule colonne du schéma en a légitimement besoin : `scan.duration_ms`,
 * qui est une durée. Toute *clé étrangère* correspond à la clé `integer` qu'elle
 * référence — une divergence que MySQL refusait et que SQLite comme PostgreSQL
 * toléraient, d'où son existence inaperçue jusqu'à ce qu'un troisième moteur la nomme.
 *
 * Rendu en **chaîne** par node-postgres, qui ne suppose pas qu'un `bigint` tient dans
 * un `number`. C'est correct et il ne faut pas le « corriger » : la valeur dépasserait
 * `Number.MAX_SAFE_INTEGER` sans prévenir.
 */
/**
 * Un entier large, **rendu comme un nombre et non comme une chaîne**.
 *
 * node-postgres rend les `bigint` en chaîne, parce qu'un entier 64 bits ne tient pas dans
 * un `number` JavaScript sans perte au-delà de 2^53. C'est prudent en général et faux
 * ici : une durée en millisecondes atteindrait 2^53 après deux cent quatre-vingt mille
 * ans. Sans ce transformateur, l'API sérialisait `"59358"` là où l'écran attend un nombre
 * — trouvé par un test de bout en bout, invisible à la lecture.
 */
export const bigIntColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'bigint',
    transformer: {
        to: (value: number | null) => value,
        from: (value: string | number | null) => (value === null || value === undefined ? null : Number(value))
    },
    ...options
});

export const boolColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'boolean',
    ...options
});

/** `Float` du modèle SQLAlchemy — scores CVSS et EPSS. */
export const floatColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'double precision',
    ...options
});

/**
 * `JSON(none_as_null=True)` côté Python, et le drapeau compte : avec le défaut de
 * SQLAlchemy, écrire `None` stockait le littéral JSON `null`, qui n'est **pas** un
 * NULL SQL. `sbom IS NOT NULL` restait donc vrai pour une charge déjà purgée, et la
 * passe de rétention repurgeait les mêmes lignes indéfiniment.
 */
export const jsonColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'json',
    ...options
});
