# 0011 — Liquibase stays, and structural DDL is written by hand

**Date:** 2026-08-22 · **Status:** accepted · **Decider:** Laurent Boucher

> Written when the question was asked, after a week in which the schema tooling produced
> three defects in a row. The alternative was seriously considered and measured before
> being rejected, which is the only reason this page is worth reading.

## Context

Three defects in one week, all from the same place — and it is worth being exact about
where, because the obvious conclusion is the wrong one.

1. **`addForeignKeyConstraint` written after the tables applies without complaint on SQLite
   and creates no constraint at all.** Referential integrity on three engines out of four,
   with nothing saying so. Found by running the changelog, not by reading it.
2. **`addColumn` makes Liquibase recreate the table on SQLite**, and the recreation leaves
   every foreign key *pointing at* that table aimed at a `<table>_temporary` that does not
   exist. One nullable column on `t_team` aimed the keys of `t_team_member`, `t_team_target`
   and `t_team_webhook` at it — access-control tables, all three. It has now fired three times.
3. **A declared `on delete cascade` does nothing on SQLite** unless
   `PRAGMA foreign_keys = ON` has been issued on the connection, which nothing does.

The tempting reading is "the abstraction is the problem, so remove the abstraction" — that
is, plain SQL per engine, which is Flyway's model. So the question was measured rather than
argued.

## What the measurement showed

**SQLite adds a column natively without touching anything else.** A plain
`alter table t_team add column webhook_url varchar(500)` adds the column and leaves the
referencing foreign key intact — verified on a real file. Defect 2 is therefore **entirely
Liquibase's recreate strategy**, not an engine limitation. Defect 1 is the same shape: the
DDL Liquibase generates is not the DDL anybody wrote.

**Defect 3 is neither.** It is a real property of SQLite, and no migration tool changes it.
Flyway would have shipped exactly the same hole.

So Flyway would have prevented two of the three, by construction: what you write is what
runs.

**And the same property is reachable without it.** The two forms were run against
`ChangelogTest` side by side: a `sql` changeset with `dbms:` doing the plain
`alter table … add column` leaves all twenty foreign keys intact, where `addColumn` on the same
table aims three of them at `t_team_temporary`. That contrast is the whole of this decision.

## Decision

**Liquibase stays.** For any structural change to a table that other tables reference, the
changeset is written as `sql` with `dbms:` rather than as `addColumn` or
`addForeignKeyConstraint` — or the change is expressed as a **new table**, which has nothing
pointing at it yet.

That takes the one property Flyway would have bought — the DDL that runs is the DDL that was
written — and applies it exactly where the abstraction has been shown to bite, while leaving
it in place where it earns its keep.

## Why not Flyway

**The duplication is the trade [0009](0009-four-engines.md) already made, deliberately.** One
changelog covers four engines in 1687 lines, with **six** type properties absorbing every
divergence found so far — `timestamp` three ways, `bool` two, `generated.id` two, plus `uuid`
and `json`. Flyway's answer is four sets of SQL, or a shared set with `{vendor}` overrides:
the same 20 baseline tables written out per engine. That is not obviously worse, and on
explicitness it is better — but it re-opens a decision that was made after measuring all four
engines, in exchange for removing a trap that two tests catch in one second.

**There is a production install.** Switching tools on a live database means reconciling
`DATABASECHANGELOG` with `flyway_schema_history` and a `baselineOnMigrate` — a one-way door,
on somebody else's data, for a gain already available without it. A migration of the migration
tool is the one migration with no way back.

**The checks that found all three defects do not care which tool is underneath.**
`ChangelogTest` applies the changelog to a real SQLite file and asserts the twenty foreign
keys by name; `SchemaParityIntegrationTest` has Hibernate validate the entities against the
schema on all four engines. Those are what turned three silent defects into three failing
builds, and they would be equally necessary under Flyway.

## What was rejected

**Flyway with per-engine SQL.** Rejected for the reasons above: it wins on explicitness,
loses on duplication, and costs a tool migration on a live install. If the four-engine
commitment is ever narrowed — one engine, or two — this decision is the one to supersede,
because the duplication argument is what carries it and that argument shrinks with the engine
count.

**Keeping `addColumn` and relying on the test.** The test does catch it, in a second, and
that is not enough: it catches it *after* somebody wrote the natural thing, and the natural
thing is the dangerous one. A rule that says "write the SQL for referenced tables" is
cheaper to follow than a failure to diagnose.

**Enabling `PRAGMA foreign_keys = ON` for SQLite and trusting the cascades.** Tempting, and
rejected as a *substitute* rather than on its merits: a deletion path whose correctness
depends on a connection-level pragma being set on every connection, including the ones a
future pool or a future maintenance job opens, is a deletion path nobody can verify by
reading it. The revocations that matter — a team's memberships, its target assignments, its
notification channel — are deleted explicitly, on every engine, and that stays true whatever
the pragma says. Turning it on as *defence in depth* remains open and is not what this
decision refuses.

## Consequences

**Writing changeset 008 requires knowing this**, so the rule is in
[`zanshin-java/README.md`](../../../zanshin-java/README.md) beside the Liquibase section —
the file somebody opens before touching the schema — and not only here.

**`ChangelogTest` asserts foreign keys by name, not by count.** A new referencing table has
to be added to that list; leaving it to be covered "by the total" is how the assertion stops
proving anything. That is now a stated requirement of the suite rather than a habit.

**The immutability of applied changesets stays a convention.** Flyway enforces it by
checksum; here "the baseline is never edited, the next change is a new changeset" is written
in the README and held by discipline. That is a real difference in the tools, recorded so
nobody discovers it during an incident.
