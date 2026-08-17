# Zanshin — NestJS control plane

The backend, ported from Python. See
[`docs/migration-nestjs-angular.md`](../docs/migration-nestjs-angular.md) for what the
port kept, dropped, and fixed along the way.

```bash
npm run start:backend                      # from the root, listens on :3000
npm test --workspace @zanshin/backend      # unit suite
npm run test:integration --workspace @zanshin/backend       # PostgreSQL, needs Docker
npm run test:integration:all --workspace @zanshin/backend   # all four engines
```

The integration tests need no database installed: `test/jest-global-setup.ts` starts a
container through testcontainers and applies the migrations, once for the whole run.
There is no "skip if the database is missing" guard — a suite that skips itself reports
green without checking anything.

## The layers, and the rule that holds them

```
api/ ──► services/ ──► repositories/ ──► persistence/ ──► database
           │                                  │
           └──────────────┬───────────────────┘
                          ▼
                       domain/          (pure, depends on nothing)
```

**A layer only knows the one below it.** This is the rule from the Python stack
(`docs/architecture/01`), carried over unchanged, with one layer more.

| Layer | Holds | Doesn't know about |
|---|---|---|
| `domain/` | The calculations that decide: fingerprint, gate verdict, audit chain, exports | Everything else — not TypeORM, not NestJS, not `pg` |
| `persistence/` | TypeORM entities, dialects, decoding of the driver's types | The repositories, the services, the API |
| `repositories/` | Data access. No business rules | The services, the API |
| `services/` | Orchestration, transactions. No SQL written here | The API |
| `api/` | Controllers, DTOs, guards | — |

`src/architecture.spec.ts` **enforces this rule** by reading the import graph: a layer
that imports from above it, or a domain file that imports a framework, fails the suite.
An architecture rule written in a document is not a rule — it is true the day it is
written and false six months later. The Python stack already did this for the agent,
whose import invariant is a security property.

### Why `domain/` is pure

It carries the calculations where a mistake raises no exception but destroys data: an
issue's fingerprint (a one-byte divergence wipes out all triage), the audit log's
integrity chain, the verdict that fails a build. Three consequences: they can be tested
exhaustively without a database; the same calculation serves the API, the scheduler and
the UI, so the verdict displayed *is* the gate's; and they would survive a change of ORM
or framework — precisely the event this project has just been through.

One exemption in the test: a `*.module.ts` is wiring, it is *the* file whose job is to
know NestJS. `domain/` gets no such exemption, because it has nothing to inject.

## The schema belongs to the migrations

`synchronize` is `false`. The migrations under `persistence/migrations/<dialect>/` are
the single source of the schema, and the entities *describe* it — each engine has its own
set, because the same intent is spelled differently on each.

This is not a precaution inherited from the period when Alembic held the schema: the
danger is `synchronize: true` itself. It modifies the database from the entities, at
startup, with no trace and no review — a column renamed in the code becomes a column
destroyed in production.

`persistence/schema-parity.integration-spec.ts` holds the two in agreement. It asks the
question `migration:generate` asks — "what would have to change for the database to look
like the entities?" — whose right answer is "nothing". It runs on whichever engine the
current campaign uses, so all four are covered in turn, and it is the only place in the
repository that checks this agreement. The two divergences it has already caught — an
index declared on the migration side but not the entity side, and the reverse — changed
no result, only its cost: nothing else would have seen them.

## Supported databases

`ZANSHIN_DB_DIALECT` accepts `postgres` (default), `sqlite`, `mysql` and `mariadb`. Each
one's limits are **announced at startup** rather than discovered in production — see
`persistence/dialects.ts`, where every warning names the consequence.

**All four pass the entire integration campaign**, each with its own set of migrations.
The table below is measured, row by row, not inferred.

| | PostgreSQL | MariaDB | MySQL | SQLite |
|---|---|---|---|---|
| Transactional scan claiming | yes | yes | yes | **no** |
| Full claim batch under contention | yes | yes | **no** | n/a |
| Millisecond timestamps | yes | yes | yes | yes |
| `NULLS LAST` | yes | no | no | yes |
| Multiple writers | yes | yes | yes | **no** |

Every "no" comes from a defect found by running, and **none of them raises an error**:

- **MySQL's `SKIP LOCKED` counts the skipped rows against the `LIMIT`.** Two claimants,
  four scans queued: the second walks away empty-handed while the queue is not empty.
  Nothing is served twice and the rest goes out on the next round — this is throughput,
  not correctness. MariaDB, measured on the same scenario, returns a full batch like
  PostgreSQL.
- **SQLite has a single writer.** A second instance on the same file would not be slow,
  it would corrupt the data. Its claiming therefore falls back to a conditional `UPDATE`
  guarded by the status, which is correct for threads within one process. Its driver
  **refuses** `FOR UPDATE` instead of ignoring it — the Python stack dropped it silently,
  producing a claim that looked transactional while handing the same scan to two
  processes in production.
- **`DATETIME` truncated to the second** was the defect that cost the Python stack MySQL:
  the audit chain covers the timestamp, so every entry failed its own verification and
  the log declared itself tampered with when nothing had been. `datetime(6)` is declared
  in a single place — `column-types.ts` — rather than column by column, where one missed
  column would be enough.

PostgreSQL remains the reference engine: it is the one on which everything is true
without reservation, and the one the code picks by default.
