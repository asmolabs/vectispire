/**
 * The supported databases, and what each one can do.
 *
 * TypeORM talks to a dozen engines, but "the driver connects" and "the system is correct on
 * it" are two different claims. This module carries the second, because the three
 * divergences below produce **no error at all**: they produce wrong data.
 *
 * Each was found by running, not by reading, back when the Python stack supported MySQL:
 *
 * 1. **`DATETIME` truncates to the second.** The audit log's integrity chain covers the
 *    timestamp to the microsecond. On an engine that truncates it, every entry fails its
 *    own verification: the log declares itself tampered with when nothing has been. That is
 *    the reason MySQL was removed.
 * 2. **`SKIP LOCKED` counts skipped rows against the `LIMIT`.** Claiming a scan then
 *    becomes partial under load: the batch comes back short while the queue is not, and
 *    real concurrency collapses silently.
 * 3. **`NULLS LAST` is a syntax error.** It appears in the backlog's ordering.
 *
 * And for SQLite, a fourth of another kind:
 *
 * 4. **SQLAlchemy, like TypeORM, silently *drops* `FOR UPDATE`.** Claiming then looks like
 *    a transaction, passes every test on a developer's machine, and hands the same scan to
 *    two processes in production. Hence `canClaimTransactionally`.
 *
 * **This module's stance: nothing is forbidden, everything is declared.** An operator
 * choosing MySQL must learn it at startup, in a message that names the consequence — not
 * months later, on discovering an audit log accusing itself.
 */

export const SUPPORTED_DIALECTS = ['postgres', 'sqlite', 'mysql', 'mariadb'] as const;
export type Dialect = (typeof SUPPORTED_DIALECTS)[number];

export interface DialectCapabilities {
    /**
     * `SELECT … FOR UPDATE SKIP LOCKED` **genuinely stops a row being handed to two
     * claimants**. That is the safety property, and the only one deciding whether several
     * processes can drain the same queue.
     */
    canClaimTransactionally: boolean;
    /**
     * A claimed batch comes back the requested size when the queue holds enough.
     *
     * **Distinct from safety, and the confusion was expensive.** MySQL counts skipped rows
     * against the `LIMIT`: a claimant asking for two can receive none
     * alors que la file n'est pas vide. Aucune ligne n'est pour autant remise deux fois —
     * measured, not assumed. The rest is taken on the next round, so this is a throughput
     * characteristic and not a correctness defect.
     */
    claimsCompleteBatches: boolean;
    /**
     * Timestamps keep the microsecond. The audit chain depends on it entirely.
     */
    preservesMicroseconds: boolean;
    /** `ORDER BY … NULLS LAST` is accepted. */
    supportsNullsLast: boolean;
    /** Several processes can write to the same database. */
    supportsConcurrentWriters: boolean;
}

export const CAPABILITIES: Record<Dialect, DialectCapabilities> = {
    postgres: {
        canClaimTransactionally: true,
        claimsCompleteBatches: true,
        preservesMicroseconds: true,
        supportsNullsLast: true,
        supportsConcurrentWriters: true
    },
    sqlite: {
        // `FOR UPDATE` is accepted and then ignored: the worst of both worlds.
        canClaimTransactionally: false,
        claimsCompleteBatches: false,
        preservesMicroseconds: true,
        supportsNullsLast: true,
        // One writer. Two instances on one file is not slow, it is
        // corrompu.
        supportsConcurrentWriters: false
    },
    mysql: {
        // **Corrected after measuring.** This flag was `false`, which was wrong: the
        // integration campaign on MySQL 8.4 shows no row is ever handed to two claimants.
        // Calling it "not transactional" would have ruled MySQL out for a bad reason, when
        // the real divergence is elsewhere.
        canClaimTransactionally: true,
        // Here is the divergence: skipped rows count against the `LIMIT`, so a batch comes
        // court sous contention. Le tour suivant prend le reste.
        claimsCompleteBatches: false,
        // `DATETIME(6)` is declared in `column-types.ts`, in one place rather than column
        // by column — one missed column would be enough to break the audit chain. The
        // connection is pinned to UTC for the same reason.
        preservesMicroseconds: true,
        supportsNullsLast: false,
        supportsConcurrentWriters: true
    },
    mariadb: {
        // **Measured, and better than MySQL.** These four flags were inherited from MySQL
        // « par prudence, pas par constat » — leur propre commentaire le disait — et trois
        // were wrong. The caution was not neutral: `canClaimTransactionally: false` sent
        // claiming down the lock-free path, where the second claimant
        // attendait la transaction du premier. Le test de concurrence expirait au bout de
        // sixty seconds, on an engine that had no problem at all.
        canClaimTransactionally: true,
        // Two concurrent claimants, four queued scans: MariaDB returns a full batch —
        // `[3, 4]` — where MySQL returns an empty list because it counts skipped rows
        // dans le `LIMIT`. Sur ce point il se comporte comme PostgreSQL.
        claimsCompleteBatches: true,
        // `datetime(6)`, like MySQL, declared once in `column-types.ts`. The audit chain
        // verifies there, which the campaign establishes.
        preservesMicroseconds: true,
        // Pas plus que MySQL : `NULLS LAST` n'existe pas dans cette famille.
        supportsNullsLast: false,
        supportsConcurrentWriters: true
    }
};

export interface DialectWarning {
    capability: keyof DialectCapabilities;
    message: string;
}

/**
 * What an operator has to know before serving a request on this engine.
 *
 * Returned rather than logged here: the caller decides whether to warn, to refuse, or to
 * demand an explicit acknowledgement through an environment variable.
 */
export function warningsFor(dialect: Dialect): DialectWarning[] {
    const capabilities = CAPABILITIES[dialect];
    const warnings: DialectWarning[] = [];

    if (!capabilities.preservesMicroseconds) {
        warnings.push({
            capability: 'preservesMicroseconds',
            message:
                `${dialect} truncates timestamps to the second (DATETIME with no precision). ` +
                "The audit log's integrity chain covers the timestamp: every entry will fail its " +
                'own verification, and the log will declare itself tampered with when nothing has ' +
                'been. Declare DATETIME(6) on every date column, or use PostgreSQL.'
        });
    }
    if (capabilities.canClaimTransactionally && !capabilities.claimsCompleteBatches) {
        warnings.push({
            capability: 'claimsCompleteBatches',
            message:
                `${dialect} counts rows skipped by SKIP LOCKED against the LIMIT: under contention, ` +
                'a claimant receives fewer scans than it asked for, sometimes none while the queue is ' +
                'not empty. No row is served twice and the rest goes out on the next round — this is a ' +
                'throughput characteristic, not a correctness defect.'
        });
    }
    if (!capabilities.canClaimTransactionally) {
        warnings.push({
            capability: 'canClaimTransactionally',
            message:
                `${dialect} does not allow genuinely transactional scan claiming: ` +
                'its driver refuses FOR UPDATE. Claiming falls back to a conditional UPDATE guarded by ' +
                'the status — correct for several threads of one process, not for several processes.'
        });
    }
    if (!capabilities.supportsNullsLast) {
        warnings.push({
            capability: 'supportsNullsLast',
            message: `${dialect} refuses "ORDER BY … NULLS LAST"; the backlog's ordering has to emulate it with a CASE expression.`
        });
    }
    if (!capabilities.supportsConcurrentWriters) {
        warnings.push({
            capability: 'supportsConcurrentWriters',
            message:
                `${dialect} accepts one writer only. A second instance on the same database ` +
                'would not be slow, it would corrupt the data. One file, one process.'
        });
    }
    return warnings;
}

/**
 * The TypeORM driver that serves this dialect.
 *
 * **The internal name and the driver's name differ, deliberately.** Zanshin says "sqlite";
 * the driver is called `better-sqlite3`. Writing the second one in the configuration would
 * leak an implementation choice all the way into an operator's environment variables, which
 * they would then have to change the day the library changes.
 */
export function driverType(dialect: Dialect): 'postgres' | 'better-sqlite3' | 'mysql' | 'mariadb' {
    return dialect === 'sqlite' ? 'better-sqlite3' : dialect;
}

/**
 * This dialect's migration directory.
 *
 * **One set per dialect, and four are genuinely needed.** SQLite knows neither
 * `uuid_generate_v4()`, nor `TIMESTAMP WITH TIME ZONE`, nor `AUTO_INCREMENT`. And **MariaDB
 * is not MySQL**: since 10.7 it carries a native `uuid` type its driver picks on its own,
 * where MySQL falls back to `varchar(36)`. Letting MariaDB read the MySQL migrations
 * produced a schema the model immediately wanted to rebuild — sixty-two statements of
 * difference, measured, including every primary key.
 *
 * No tool translates one into the other, and mixing them would fail the first migration run
 * on whichever engine is not the original.
 */
export function migrationDirectory(dialect: Dialect): 'postgres' | 'mysql' | 'mariadb' | 'sqlite' {
    return dialect;
}

/** Normalizes whatever an operator may have written in the configuration. */
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
        throw new Error(`Unsupported dialect "${value}". Expected one of: ${SUPPORTED_DIALECTS.join(', ')}.`);
    }
    return dialect;
}
