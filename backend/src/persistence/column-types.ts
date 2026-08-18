import { type Dialect, parseDialect } from './dialects';

/**
 * The dialect this process serves, read once.
 *
 * **Read at import and not per call**: the column definitions are module constants,
 * evaluated when TypeORM loads the entities. A process talks to one database only, so one
 * read is enough — and changing it midway would make no sense.
 */
export const DIALECT: Dialect = parseDialect(process.env.ZANSHIN_DB_DIALECT ?? 'postgres');

export const isMySql = (dialect: Dialect = DIALECT): boolean => dialect === 'mysql' || dialect === 'mariadb';

/**
 * Type spellings, per dialect.
 *
 * PostgreSQL and MySQL do not name the same things the same way, and **TypeORM does not
 * translate**: `timestamp with time zone` or `double precision` sent to MySQL produce a
 * syntax error when the table is created. This module is the only place those differences
 * exist.
 *
 * **Timestamp precision is the critical point.** The audit log's integrity chain covers the
 * timestamp serialized as ISO, hence to the millisecond. A MySQL `DATETIME` with no
 * precision truncates to the second: every entry would then fail its own verification and
 * **the log would declare itself tampered with when nothing had been**. That is why the
 * Python stack removed MySQL. `datetime(6)` removes the cause — and the precision is
 * declared here, in one single place, rather than column by column where one missed column
 * would be enough to break the chain.
 *
 * `datetime` and not `timestamp`: MySQL's `TIMESTAMP` stops in 2038 and converts according
 * to the session timezone. The data source pins the connection to UTC, which makes
 * `datetime` unambiguous while avoiding the 2038 boundary.
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
    // Six digits: the audit chain needs three, and the margin costs nothing.
    timestamp: { type: 'datetime', precision: 6 },
    string: 'varchar',
    // MySQL n'a pas de type `uuid`. `varchar(36)` porte la forme canonique que
    // `@PrimaryGeneratedColumn('uuid')` produces, and stays compatible with the foreign
    // keys that reference it.
    uuid: 'varchar',
    text: 'text',
    int: 'int',
    bigint: 'bigint',
    // TypeORM emits `tinyint(1)`, which the driver reads back as a boolean.
    bool: 'boolean',
    float: 'double',
    json: 'json'
};

/**
 * SQLite knows only five storage classes, and infers its own from the type's **name**.
 *
 * Les orthographes ci-dessous sont donc choisies pour tomber dans la bonne classe :
 * `varchar` and `text` map to TEXT, `integer` to INTEGER, `real` to REAL. Nothing is
 * checked on write — SQLite accepts any value in any column — which moves the rigour onto
 * the entities and the migrations.
 *
 * **`datetime` is text, and that is what saves the audit chain.** The driver serializes a
 * `Date` to ISO at millisecond precision, exactly the precision the log's hash covers. This
 * is the trap that cost the Python stack MySQL — a `DATETIME` truncated to the second made
 * every entry fail its own verification there — and it does not arise here, provided
 * TypeORM is never left to choose an integer.
 */
const SQLITE: ColumnSpelling = {
    timestamp: { type: 'datetime' },
    string: 'varchar',
    // Pas de type `uuid` : la forme canonique tient dans du texte, comme sous MySQL.
    uuid: 'varchar',
    text: 'text',
    int: 'integer',
    // SQLite has one 64-bit integer; `bigint` and `integer` name the same storage there.
    bigint: 'bigint',
    bool: 'boolean',
    float: 'real',
    // Stored as text. TypeORM serializes and reads back, which is what a `json` column expects.
    json: 'json'
};

/**
 * **MariaDB is not MySQL**, and the whole difference fits on one line.
 *
 * Since 10.7 it carries a native `uuid` type, which its driver picks on its own for a
 * generated key. Declaring `varchar` here would therefore be writing one thing and getting
 * another: TypeORM corrected it silently, and the schema produced by the MySQL migrations
 * immediately demanded sixty-two statements of repair — every primary key included.
 *
 * Le type natif est en outre le bon choix : seize octets au lieu de trente-six, et un ordre
 * de tri qui a un sens.
 */
const MARIADB: ColumnSpelling = { ...MYSQL, uuid: 'uuid' };

export const SPELLING: ColumnSpelling =
    DIALECT === 'sqlite' ? SQLITE : DIALECT === 'mariadb' ? MARIADB : isMySql() ? MYSQL : POSTGRES;

/** La longueur d'un UUID en forme canonique, quand le dialecte exige une longueur. */
export const UUID_LENGTH = 36;
