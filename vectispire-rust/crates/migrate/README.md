# vectispire-migrate

The control plane's schema migrations, run the way **Flyway 12.4** runs them for the Java control plane.
Phase 0, task 0.1 of the control-plane port (`docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md`,
§3.3). Not shipped; nothing links it yet.

**Why its own crate.** The history table decides everything: an installation the Java control plane
migrated must continue under Rust and, while both exist, go back. `refinery` keeps `refinery_schema_history`
with a SipHash checksum and `sqlx::migrate` keeps `_sqlx_migrations` with SHA-384, so neither can read or
write `flyway_schema_history` the way Flyway does.

```rust
let database = vectispire_migrate::Database::MySql(pool);        // or ::PostgreSql(pool)
let report = vectispire_migrate::run(&database, &Options::default()).await?;   // validate, then migrate
let validation = vectispire_migrate::validate(&database, &Options::default()).await?;  // validate only
```

The pool needs at least two connections: one holds Flyway's lock and writes the history, the other runs
the migration — as Flyway does.

## What is Flyway's, exactly

All of it was read from the 12.4.0 sources (`flyway-core`, `flyway-mysql`, `flyway-database-postgresql`)
and is proven by `tests/oracle.rs` against the real thing.

| | Flyway 12.4.0 | here |
|---|---|---|
| **Checksum** | `ChecksumCalculator`: CRC-32 over the bytes of each line read by `BufferedReader.readLine` (`\n`, `\r`, `\r\n` ended, terminators dropped), a UTF-8 BOM removed from the first line only, cast to a Java `int`. Computed over the file **as stored**: placeholders are replaced for repeatable migrations only (`SqlMigrationResolver.getChecksumForLoadableResource`) | `checksum.rs` |
| **History table** | `getRawCreateScript` per engine, the `_pk` constraint and `_s_idx` index, the insert of `JdbcTableSchemaHistory`, `installed_rank` = last + 1 (first = 1), `installed_by` = `SUBSTRING_INDEX(USER(),'@',1)` / `current_user`, `type` = `SQL`, description and script abbreviated as `AbbreviationUtils` does | `history.rs` |
| **Description / version** | `V<version>__<description>.sql`, `_` in the description read as a space | `set.rs`, `version.rs` |
| **Validation** | `MigrationInfoImpl.validate` with `validateOnMigrate`, `outOfOrder=false`, `ignoreMigrationPatterns=*:future` and the `*:pending` that `migrate` adds, with Flyway's sentences | `validate.rs` |
| **MySQL lock** | `SELECT GET_LOCK('Flyway-<hash>', 10)` every 100 ms until held, `RELEASE_LOCK` after; `<hash>` is `"`schema`.`flyway_schema_history`".hashCode()` | `history.rs` |
| **PostgreSQL lock** | `pg_try_advisory_xact_lock(0x466C79776179 + hash)` inside a transaction (Flyway 12's default `postgresql.transactional.lock`), retried a second apart, 50 times | `history.rs` |
| **One migration at a time** | `group=false`: the lock is taken, the history re-read, one pending migration applied and recorded, the lock released; repeat | `lib.rs` |
| **Failure** | PostgreSQL: the migration's transaction rolls back, no row. MySQL (DDL commits as it runs): a row with `success = false`, and the next start refuses | `lib.rs` |
| **Non-empty schema** | no history table but objects in the schema: refused (`baselineOnMigrate` is off) | `lib.rs` |

**Placeholders** are `MigrationDialect`'s eight types, per engine, in the same order; a configured value
that redefines one is refused with `MigrationPlaceholders`' sentence (`dialect.rs`). **The layout rules**
of `MigrationLayoutTest` run over the embedded files at every start (`layout.rs`): a version lives in
`common` once or in every vendor directory, V1–V39 never move, and a common migration names no engine.

**Not implemented, on purpose:** `clean`, `baseline`, `repair`, repeatable and undo migrations, `outOfOrder`,
non-transactional migrations on PostgreSQL (`CREATE INDEX CONCURRENTLY`…, refused with the statement
named), Flyway's own `${flyway:…}` placeholders. The control plane's configuration uses none, and each
would need its own port. **Not here yet:** the schema-parity check that replaces `ddl-auto: validate`
(task 0.2, `cp-db`).

**The files are not copied.** `build.rs` embeds `vectispire-core`'s `db/migration` at build time, so a
new migration is in this crate with the next build, and the Java and Rust sides can never read two
different sets.

## Tests

```sh
cargo test -p vectispire-migrate                 # unit tests, and tests/engines.rs on MySQL 9.4 and PostgreSQL 17 (Docker)
oracle/check-oracle.sh                           # tests/oracle.rs against the real Flyway (Docker, JDK 25, Gradle's cache)
```

- `tests/engines.rs` — what a start accepts and refuses, on both engines: a tampered file, an applied
  version without its file, a database ahead of the files, an older file never applied, a failed row, a
  renamed migration, objects without a history, a migration that fails, two runners started together, a
  configured column type. And **the checksums of every file, held to the values the real Flyway
  recorded** (`reference/migrate/checksums-*`), offline.
- `tests/oracle.rs` — the real Flyway (`oracle/FlywayOracle.java`, source-launched on `vectispire-core`'s
  runtime classpath so the placeholders and locations are the application's own):
  1. Java migrates an empty database → every checksum and description Rust computes equals what Flyway
     stored; Rust validates and is a no-op (develop's files, and the 0.11.1 line's, V91 included).
  2. Rust migrates an empty database → Flyway validates it, has nothing left to apply, and the schema
     (`information_schema` dump) equals the one Flyway produced.
  3. Java migrates to V89, Rust applies the rest, Java starts again and accepts it.
  4. A Java and a Rust instance start together on an empty database: every migration is applied once.
- `reference/migrate/` — what Flyway wrote (checksums, schema dump), committed; rewritten only with
  `VECTISPIRE_REFERENCE_WRITE=1`, after a migration was added.
- Every test that pins a guard was mutation-checked: `mig/mutate.py`'s list is in the commit message
  of the commit that added it.
