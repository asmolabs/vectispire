# 0027 — Common migrations with type placeholders; vendor directories for structural divergence

**Date:** 2026-09-26 · **Status:** accepted · **Amends:** [0013](0013-flyway-multi-dialect-migrations.md) · **Decider:** Laurent Boucher

## Context

[0013](0013-flyway-multi-dialect-migrations.md) chose Flyway with one native SQL set per engine,
and named the condition under which to revisit it: *"if a schema change turns out to be identical
across every engine for a long enough stretch that the duplication is pure ceremony"*. The sets were
measured on 2026-09-26, after thirty-nine migrations, each written three times under
`db/migration/{mysql,postgresql,sqlite}`:

* **Thirteen are identical in substance across the three.**
* **Most of the remaining differences are type names**: a timestamp is `datetime(6)`, `timestamp
  with time zone` or `numeric`; an identity is `bigint auto_increment`, `bigint generated always as
  identity` or `integer primary key autoincrement`; a boolean is `bit(1)` with `b'0'`, `boolean`
  with `false`, or `boolean` with `0`; a long text is `longtext` or `text`.
* **Structural divergence is rarer**: MySQL's named foreign-key constraints (it parses an inline
  `references` and discards it), column changes (`modify`, `alter column … type`, a table rebuild or
  nothing on SQLite), date arithmetic, data repairs.

The duplication is not only typing. Three copies are three chances to disagree, and the MySQL set
already disagrees *with itself*: V1, V4 and V14 declare booleans as `bit(1)`, V8, V25 and V27 as
`boolean` — which MySQL stores as `tinyint(1)`. Nothing decided that; each author copied whichever
neighbour was open.

0013's reason for native SQL still holds and is not reopened here: a migration abstraction that
picks the type for you is how `datetime` without its precision reaches MySQL, and the audit chain
then reports tampering that never happened. The question is whether the types can be named once
*without* hiding them.

## Decision

**From V40 on, a migration that differs between engines only by its column types is written once,
under `db/migration/common`, with type placeholders; a migration whose structure diverges is written
in each of the three vendor directories.** Flyway reads
`classpath:db/migration/common,classpath:db/migration/{vendor}`.

**The placeholders are set per engine by `MigrationPlaceholders`, a `FlywayConfigurationCustomizer`,
from one table in `MigrationDialect`** (both in `core/config`):

| Placeholder | MySQL | PostgreSQL | SQLite (fixture) |
|---|---|---|---|
| `${ts}` | `datetime(6)` | `timestamp with time zone` | `numeric` |
| `${id}` | `bigint auto_increment primary key` | `bigint generated always as identity primary key` | `integer primary key autoincrement` |
| `${bool}` | `bit(1)` | `boolean` | `boolean` |
| `${true}` / `${false}` | `b'1'` / `b'0'` | `true` / `false` | `1` / `0` |
| `${text}` | `longtext` | `text` | `text` |
| `${double}` | `double` | `double precision` | `double` |

That table *is* the answer to 0013's concern: the type each engine receives is spelled in one file,
next to the reason `${ts}` is `datetime(6)`, and nothing translates it on the way to the server.
Flyway substitutes the text and the engine runs it.

* **The engine is identified as Spring Boot identifies it for `{vendor}`** — the data source's URL,
  through `DatabaseDriver` — so the directory read and the types substituted cannot disagree. An
  engine with no mapping stops the start; a `spring.flyway.placeholders.*` property that tries to
  redefine one of these types stops it too.
* **`${id}` carries `primary key` itself**, and a new table writes `id ${id},`. SQLite forces this:
  only the exact phrase `integer primary key` makes the column the rowid, `autoincrement` is refused
  anywhere else, and `integer primary key` without it hands a deleted last row's id to the next
  insert.
* **`${bool}` is `bit(1)` on MySQL** — the type Hibernate maps a boolean to there, and what V1 used —
  which ends the drift described above for everything written from now on.

**The rule, enforced.** A version lives either in `common`, once, or in all three vendor
directories — never in one or two of them, never in `common` and a vendor directory. A file in
`common` names no engine: `MigrationLayoutTest`, in the unit suite, refuses the rest and fails the
build. It also refuses a file name Flyway would silently skip, an unknown placeholder,
`${id} primary key`, a directory no engine maps to, a new vendor triple that is byte-identical (it
belongs in `common`), and any of V1–V39 leaving the vendor directories. The engine tokens it refuses
in `common` include `auto_increment`, `autoincrement`, `generated always`, `datetime`, `timestamp`,
`bit(`, `boolean`, `longtext`, backticks and double quotes, and — because they are structural —
`references`, `modify`, `alter column` and date functions.

**A foreign key is structural divergence.** MySQL needs a named `alter table … add constraint`;
SQLite cannot add a constraint after `create table`. A table that carries a foreign key is
therefore written three times, as V19 and V39 were.

**V1–V39 are not rewritten.** Flyway validates the checksum of every applied migration and refuses
to start when one changed, so moving the thirteen identical files into `common`, or editing any file
to use a placeholder, would stop every existing installation. Enabling the placeholders does not
move those checksums: in Flyway 12.4 `SqlMigrationResolver` computes a versioned migration's
checksum with `ChecksumCalculator` over the raw resource, and only a repeatable migration's is taken
after placeholder replacement. Placeholder replacement was already on — it is Flyway's default —
and none of the thirty-nine files contains `${`.

**Proven on the engines.** The campaign adds a test-only location holding a common probe migration,
`V9000__placeholder_probe`, that uses every placeholder; `MigrationPlaceholdersIntegrationTest`
applies it through the application's own Flyway on MySQL, PostgreSQL and SQLite and reads each
engine's catalog (`datetime(6)`, `timestamp with time zone`, an `ALWAYS` identity, `integer` primary
key) and round-trips a millisecond, both boolean defaults, text past 64 KiB, a double, and an
identity that does not reuse a deleted id. The probe is never on the production classpath.

### Why not Liquibase again

It is the tool that writes a schema once, and it was considered.

* **Licence.** Liquibase Community from 5.0 is published under the Functional Source License
  (FSL-1.1-ALv2), which is not an OSI open-source licence. Part of Vectispire's job is governing
  its customers' licences, and it ships under Apache 2.0 ([0012](0012-apache-2-0.md)); a non-OSI
  component in its own core is a contradiction a customer's procurement will find before we explain
  it.
* **4.x is end of life**, so staying on the last Apache-licensed line means taking no more fixes.
* **0013's reasons have not changed.** A database-agnostic changelog translates types, which is the
  step that hid `datetime(6)`.
* **The history would have to move.** Every existing installation carries a
  `flyway_schema_history`; switching tools means a `changelogSync` run on each of them, and a
  migration of the migration tool is a failure mode customers experience, not us.

## Consequences

**What is bought.** A migration that only adds tables and columns is written once, and the three
engines cannot drift on it. The types are decided in one reviewed place rather than re-decided by
each author.

**What it costs.** A reader of a common migration looks up `${ts}` once, in `MigrationDialect`. And
there are now two places a version may live; the test is what keeps that from becoming "any place".

**A value in the table is as frozen as an applied migration.** Flyway does not replay what it has
applied, so changing, say, `${text}` later changes the columns of *new* installations only, and the
two populations diverge silently. A type change is a new migration that alters the existing columns
— written in the vendor directories, because a column change is structural — and only then a
change to the table.

**When to revisit.** If a structural divergence turns out to recur in the same shape (a foreign key
per new table, for instance) often enough that a second kind of placeholder would carry it without
hiding it; or if the supported engine set changes, in which case the table gains a column and every
placeholder must answer on the new engine before the first common migration applies there.
