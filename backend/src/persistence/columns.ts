import { ColumnOptions } from 'typeorm';
import { SPELLING, UUID_LENGTH } from './column-types';

/**
 * Shared column types, so that every entity declares them the same way.
 *
 * **The schema belongs to the migrations**, one set per dialect under `migrations/`, and
 * TypeORM runs with `synchronize: false`. These entities *describe* existing tables; they
 * do not create them. `schema-parity.integration-spec.ts` is what checks the description
 * stays exact — it asks the question `migration:generate` asks, whose right answer is
 * "nothing".
 *
 * Primary keys do not use these helpers: `@PrimaryColumn` requires `nullable?: false`,
 * which `ColumnOptions` does not guarantee. They declare their type in the clear, which
 * stays readable for the two that exist.
 */

/**
 * An instant, with its timezone.
 *
 * It used to be `timestamp without time zone`, reproduced from the SQLAlchemy schema. That
 * choice produced five distinct defects in this port: node-postgres returned a `Date`
 * interpreted in the machine's timezone, TypeORM rehydrated columns the entity declared as
 * text, and a session was born two hours in the past in summer. Each needed a workaround —
 * `pg-types.ts`, a text conversion, canonicalization inside the audit fingerprint — and
 * each was forgotten at least once.
 *
 * `timestamptz` removes the cause: the database stores an absolute instant, the driver
 * returns a `Date`, and there is nothing left to convert or canonicalize.
 */
export const timestampColumn = (options: ColumnOptions = {}): ColumnOptions =>
    ({
        ...SPELLING.timestamp,
        ...options
    }) as ColumnOptions;

/** The default length across this whole schema. */
export const stringColumn = (length = 255, options: ColumnOptions = {}): ColumnOptions =>
    ({
        type: SPELLING.string,
        length,
        ...options
    }) as ColumnOptions;

/**
 * A foreign key to a table with a UUID primary key.
 *
 * `uuid` and not `char(36)`: TypeORM maps this type per dialect — native `uuid` on
 * PostgreSQL and MariaDB, `varchar(36)` on MySQL which has none. Writing `char(36)` by hand
 * would give a type incompatible with the primary key it references, which
 * `@PrimaryGeneratedColumn('uuid')` deliberately lets TypeORM choose.
 */
export const uuidColumn = (options: ColumnOptions = {}): ColumnOptions =>
    ({
        type: SPELLING.uuid,
        // **The length belongs to the type, not to the dialect.** `varchar` does not compile
        // without it; `uuid` — native on PostgreSQL as on MariaDB — refuses it. The condition
        // used to test the engine's name, and MariaDB fell on the wrong side of it.
        ...(SPELLING.uuid === 'varchar' ? { length: UUID_LENGTH } : {}),
        ...options
    }) as ColumnOptions;

/** No length, for what must not be truncated. */
export const textColumn = (options: ColumnOptions = {}): ColumnOptions => ({ type: SPELLING.text, ...options }) as ColumnOptions;

export const intColumn = (options: ColumnOptions = {}): ColumnOptions => ({ type: SPELLING.int, ...options }) as ColumnOptions;

/**
 * A wide integer, **returned as a number and not as a string**.
 *
 * node-postgres returns `bigint` as a string, because a 64-bit integer does not fit in a
 * JavaScript `number` without loss beyond 2^53. That is prudent in general and wrong here:
 * a duration in milliseconds would reach 2^53 after two hundred and eighty thousand years.
 * Without this transformer the API serialized `"59358"` where the screen expects a number —
 * found by an end-to-end test, invisible to a reading.
 *
 * One column of the schema legitimately needs the width: `scan.duration_ms`, a duration.
 * Every *foreign key* matches the `integer` key it references — a divergence MySQL refused
 * while SQLite and PostgreSQL tolerated it, which is why it went unnoticed until a third
 * engine named it.
 */
export const bigIntColumn = (options: ColumnOptions = {}): ColumnOptions =>
    ({
        type: SPELLING.bigint,
        transformer: {
            to: (value: number | null) => value,
            from: (value: string | number | null) => (value === null || value === undefined ? null : Number(value))
        },
        ...options
    }) as ColumnOptions;

export const boolColumn = (options: ColumnOptions = {}): ColumnOptions => ({ type: SPELLING.bool, ...options }) as ColumnOptions;

/** CVSS and EPSS scores. */
export const floatColumn = (options: ColumnOptions = {}): ColumnOptions => ({ type: SPELLING.float, ...options }) as ColumnOptions;

/**
 * A JSON payload, where a null value must be a **SQL NULL** and not the JSON literal
 * `null`.
 *
 * The distinction is not academic: with the JSON literal, `sbom IS NOT NULL` stayed true
 * for a payload that had already been purged, and the retention pass repurged the same rows
 * indefinitely.
 */
export const jsonColumn = (options: ColumnOptions = {}): ColumnOptions => ({ type: SPELLING.json, ...options }) as ColumnOptions;
