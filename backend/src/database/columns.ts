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
export const timestampColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'timestamp without time zone',
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
export const uuidColumn = (options: ColumnOptions = {}): ColumnOptions => ({
    type: 'uuid',
    ...options
});
