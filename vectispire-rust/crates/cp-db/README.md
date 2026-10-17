# vectispire-cp-db

The control plane's database layer (plan, Phase 0, task 0.2): the Rust side of `spring.datasource`,
Spring's transactions, the JPA criteria and `ddl-auto: validate`. **Not shipped; the Java control plane
is the product.**

## What is here

| Module | What it holds | Java counterpart |
|---|---|---|
| `settings` | the `jdbc:mysql://…` / `jdbc:postgresql://…` URL operators already write, the pool with Hikari's defaults | `spring.datasource`, HikariCP |
| `db` | `Db`, a pool on either engine, opened with the session the Java drivers open | the `DataSource` |
| `tx` | `Tx`, `Mode`, `retry_on_lock_conflict` | `@Transactional`, `REQUIRES_NEW`, `AuditLogService.LOCK_BACKOFF` |
| `query` | `VisibleSelect`: a `SELECT` on a target's rows that cannot be built without a `Visibility` | `IssueSpecifications.visible`, `RowVisibility` |
| `visibility` | `Visibility`, `ScanTarget` | `common.domain.access.Visibility` |
| `parity` | declared tables against `information_schema`, every disagreement at once | `SchemaParityIntegrationTest`, `ddl-auto: validate` |
| `types` | `TextUuid` (`char(36)` ids), `UtcInstant`, microsecond `now()` | `@JdbcTypeCode`, `CoreConfiguration.clock()` |
| `store` | the pattern for checked fixed queries, once per engine | the 319 `@Query` methods |

`Engine` is `MySql` or `PostgreSql`, matched exhaustively everywhere.

## What is decided, and why

- **`sqlx`, not an ORM.** SeaORM over the same schema would reintroduce the "two authorities" risk
  `ddl-auto: validate` exists to avoid. `sea-query` builds only the dynamic filters.
- **`Db` is an enum, not `sqlx::Any`.** `Any` erases the engine and with it the compile-time check of
  each query. A persistence module writes each fixed query once per engine, in the engine's own
  placeholders, and matches on `Db`.
- **The session is the Java drivers'.** sqlx adds `PIPES_AS_CONCAT` (changes what `||` means) and its
  handshake makes the server add `IGNORE_SPACE` (turns every function name into a reserved word); both
  are undone, so the same SQL means the same thing under either control plane. The session test reads
  `sql_mode`, the zone, the collation and the isolation level from each live server.
- **Instants are microseconds, UTC**, as `CoreConfiguration.clock()` makes them. The columns written
  before the placeholders (`t_siem_config`, `t_license_policy`…) are `timestamp` to the second on MySQL
  and `timestamp without time zone` on PostgreSQL: `UtcInstant` reads them.
- **`char(36)` ids are text.** sqlx's own `Uuid` binds sixteen bytes on MySQL; the feature is off.
- **A transaction of its own is a second `begin`.** There is no ambient transaction to join, so
  `REQUIRES_NEW` is the plain case, and joining is passing `&mut Tx` down.
- **Lock conflicts are the codes Spring translates** to `PessimisticLockingFailureException`
  (MySQL 1205, 1213, 3572; PostgreSQL 55P03, 40P01, 40001), retried as a whole unit — the engine rolled
  the transaction back — with the audit log's 50 ms doubling backoff. Timeouts and a real deadlock are
  both tested on each engine.
- **A row naming both a repository and an image is the repository's** (0.11.1): an image grant matches
  only rows whose repository column is empty. Identifiers are written into the statement in lists of a
  thousand, because bound they exceed PostgreSQL's 65,535 parameters.

## The guarantee that a query on a target needs a `Visibility`

"A route naming a target must resolve a `Visibility` and pass it to the query" (AGENTS.md) is a compile
error, not a review finding. A target table is a *marker* (`Issues`, `Scans`…), not a `sea_query::Iden`,
so it cannot be put in a `FROM`; the only way to read it is `VisibleSelect`, whose constructors take the
`Visibility`; its fields are private; `TargetTable` is sealed. `tests/ui/*.rs` are the programs that must
not compile, with the compiler's refusal beside each (`trybuild`).

What types cannot see — a table named as a string in `Alias::new("t_issue")` or in raw SQL — is
`cp-arch-tests`' (task 0.8): it must read every SQL string and refuse a target table outside `VisibleSelect`.

## The two offline query caches

`sqlx::query!` asks a real database to describe each statement while compiling. The answer is kept in
`crates/cp-db/.sqlx/`, so a build needs no database (`SQLX_OFFLINE=true`).

- **One directory, both engines.** Offline, the macro reads the cached file's `db_name` and expands for
  that driver, so the files of both engines can sit together.
- **Every statement starts with its engine's tag**, `/* mysql */` or `/* postgres */`. The file is named
  after a hash of the SQL text alone; the same statement on both engines would name one file twice.
- **Each engine's queries are a feature** (`mysql-queries`, `postgres-queries`, both on by default).
  Pointed at one `DATABASE_URL`, the macro would try to describe the other engine's statements against
  it and fail, so `crates/cp-db/scripts/sqlx-prepare.sh` compiles one engine's at a time against a
  throwaway server of that engine, migrated by the real Flyway.
- **A module crate's statements use the same script**, named after the crate: `sqlx-prepare.sh check cp-audit`
  regenerates `crates/cp-audit/.sqlx/`. Its database is named in a `.env` the script writes beside that crate's
  manifest and removes, never as `DATABASE_URL` in the environment — cp-db's own macros would then describe their
  statements against the one engine up, and fail for the other; without a `.env`, a crate compiles from its cache.
- `sqlx-prepare.sh prepare` rewrites the caches; **`sqlx-prepare.sh check`** regenerates into a scratch
  directory, fails on any difference from the committed one (a removed query leaves its file behind; a
  schema change changes the answers), then compiles offline with both engines on. A schema change and its
  cache travel in one commit.

## Tests

`cargo test -p vectispire-cp-db` — Docker required; its absence fails the run.

- `tests/engines.rs`: MySQL 9.4 and PostgreSQL 17 by digest, each migrated by **the real Flyway 12.4.0**
  from the repository's migrations (`vectispire-migrate` will replace the Flyway container later, and
  be checked against the same one). Session, schema parity (six tables, one with engine-specific
  spellings), a deliberate disagreement reported at once, every column type read back to the bit, a
  read-only transaction refusing a write, `REQUIRES_NEW`, a lock timeout and a real deadlock retried,
  visibility on rows naming a repository, an image, or both, a grant of 70,000 targets as one statement,
  and the checked queries round-tripping.
- `tests/ui_compile_fail.rs`: the four ways to forget a `Visibility`.
- Unit tests: URL parsing and refusals, pool validation, the retry policy, the SQL written for each
  visibility, the parity comparison.

Containers and networks are `vs-rs-db-*` (`vs-rs-sqlx-*` for the cache script), removed on drop.

## Not here yet

- The migration runner (`vectispire-migrate`, task 0.1): the tests use Flyway itself until it lands.
- The `Visibility` resolution from grants (`cp-access`, Phase 1): this crate applies one, it does not make one.
- The table declarations of each module (`parity::Table`) and its fixed queries: each module's persistence declares its own.
- `cp-arch-tests`' reading of SQL strings (above), and a check that every `query!` carries its tag.
