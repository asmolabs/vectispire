# Study: SeaORM for the Rust control plane's persistence

**Date:** 26 October 2026 · **Tree studied:** the Rust port, `rust/p3-4-gate` @ `0081a85c3`, with SeaORM 2.0.4
resolved beside it in a throwaway worktree · **Status:** proposal, no code written · **In French:**
[Étude : SeaORM pour la persistance du plan de contrôle Rust](../fr/2026-10-26_etude_seaorm_rust.fr.md)

Asked on 2026-10-26: "for the Rust part, study a solution like SeaORM".

## The question

The Rust port of the control plane writes its database access by hand. Would an ORM — SeaORM, the one built
on the libraries the port already uses — make that code smaller and safer, at what cost, and for which part?

## What the port has today

`cp-db` and the module crates (`cp-issues`, `cp-inventory`, `cp-scanning`, `cp-gate`, `cp-agents`, `cp-rules`…)
talk to MySQL and PostgreSQL through **sqlx 0.9**, in three styles:

| Style | Count | Checked | Where |
|---|---|---|---|
| `sqlx::query!`, `query_as!`, `query_scalar!` | 372 | **at compile time, against both engines**, from the two offline caches in `.sqlx/` | fixed queries |
| `sea-query` through `VisibleSelect` | a few builders | at run time; the visibility guard is in the type | dynamic selects on a target's rows |
| `sqlx::query(AssertSqlSafe(…))` | **317** | **not at all**, until a test runs them | the repositories' CRUD — 83 in `cp-inventory`, 60 in `cp-issues`, 40 in `cp-scanning`, 30 in `cp-gate`, 28 in `cp-agents` |

The third style is where the cost is. A typical repository method writes its statement **twice**, once per
engine (`?` against `$1`), matches on the transaction's engine to run it, and reads the row back **by column
name at run time** through a hand-written macro (`parse_issue_row!`). A misspelt column, a wrong type or a
placeholder count that disagrees is found by a test, or not at all.

The schema belongs to the Java side's Flyway migrations, applied by `vectispire-migrate` with Flyway's own
checksums, and `parity::check` compares the declared tables with what they built — the Rust side of
`ddl-auto: validate`.

## What SeaORM 2.0 is, here

SeaORM is an ORM written **on sqlx and sea-query**, the two libraries the port already uses: entities derived
from structs, a typed `Column` per table, `find`/`filter`/`update_many` that render for the engine at hand,
`ActiveModel` for partial updates, relations.

Measured against the port:

- **The same foundations.** SeaORM 2.0.4 resolves to `sqlx 0.9.0` and `sea-query 1.0` — the port's own versions.
  No second sqlx, no second query builder.
- **20 new crates**, almost all derive and procedural-macro tooling (`sea-orm`, `sea-orm-macros`,
  `sea-query-derive`, `sea-bae`, `darling`, `derive_more`, `derive-where`, `async-stream`, `async-trait`,
  `itertools`, `ordered-float`, `pluralizer`…). Each needs a `cargo vet` audit or a named exemption, and a
  licence in `deny.toml`.
- **One new duplicate version**: `heck` 0.4 beside 0.5, used at build time only. `deny.toml` denies multiple
  versions, so it would be named in its `skip` list, with the reason.
- No self-referencing `unsafe` crate (`ouroboros`, which SeaORM 1 pulled in, is gone in 2.0).

## What it would bring

- **The 317 unchecked queries become typed.** `Issue::find_by_id(id)`,
  `Issue::find().filter(issue::Column::Id.is_in(ids))`: columns are an enum, a misspelt one does not compile,
  and the engine's placeholders are SeaORM's business — the statement is written once, not twice.
- **Rows read into structs by the derive**, not by hand-written `try_get` per column.
- **Conditional updates count their rows** (`update_many().col_expr(…).filter(…).exec()` returns the rows
  affected): the claims and leases the Java side settles by row count — the ticket sweep's claim of V93, the
  leader's lease — are expressible as they are.

## What it would cost, and what it would not give

- **No compile-time check against the schema.** `query!` checks a statement against the real schema of both
  engines; a SeaORM entity is checked against nothing until it runs. The answer is the one Hibernate's
  `validate` gives the Java side: extend `parity::check` to compare each entity's columns and types with the
  migrated schema, on both engines, in the suite — a test, not a hope.
- **Transactions.** The port's `Tx` is an enum over the two engines' sqlx connections, and SeaORM has its own
  `DatabaseTransaction`. A unit of work that mixes a checked `query!` and an entity call must run on one
  connection. SeaORM can be built on the port's existing pools; **whether one transaction can serve both is
  the open question**, and the spike below answers it first.
- **The visibility guard.** `VisibleSelect` makes a query on a target's rows unbuildable without a `Visibility`.
  A SeaORM `Select<Entity>` would need the same wrapper, or the guard is weaker than today.
- **Migrations stay Flyway's.** Never `sea-orm-migration`: the schema is the Java side's, applied with Flyway's
  checksums by `vectispire-migrate`, and a second authority over it is the defect `ddl-auto: validate` exists
  to prevent. Entities may be generated once from the schema (`sea-orm-cli generate entity`), then reviewed and
  kept by hand.
- **The supply chain**: the 20 audits above, once.

## Options

1. **As it is.** Keeps the compile-time checks, and the 317 hand-written, duplicated queries.
2. **SeaORM everywhere.** Rewrites the 372 checked queries too, and loses the port's one check against the real
   schema at compile time. Not recommended.
3. **Hybrid.** SeaORM for the repositories' CRUD — the 317 unchecked queries — and `query!` kept for the fixed
   statements, which stay checked against both engines. `sea-query` stays where it is.

## Recommendation

**Option 3, gated by a spike on one module.** Port `cp-issues`' repository (60 queries) and require:

- the golden replay of the Java side's traffic and the module's tests green on MySQL and PostgreSQL;
- one transaction running both a `query!` and an entity call, or the hybrid is off;
- `parity::check` extended to the module's entities, failing on a column renamed in a mutant;
- the visibility guard kept in the type;
- the lines and the duplicated statements counted before and after.

**Cost**: 2 to 3 developer-days for the spike, the 20 supply-chain audits included. If it holds, about 8 to 12
for the other repositories, module by module, each behind its own golden replay. The port stays paused until
this is decided; nothing here changes the Java side.
