# Agents

Zanshin is a **NestJS + Angular** application in a single npm workspace. It was ported
from Python/Reflex; the Python tree is gone. If you find instructions telling you to
install Reflex skills, set up a virtualenv, or run `reflex init`, they are stale — this
file used to contain exactly that.

## The stack

| | |
|---|---|
| Backend | NestJS 11, TypeORM, `backend/` — see [`backend/README.md`](backend/README.md) |
| Frontend | Angular 21, Optimus UI, `frontend/` — see [`frontend/README.md`](frontend/README.md) |
| Database | PostgreSQL (default), MySQL, MariaDB, SQLite — one migration set each |
| Node | pinned by `.nvmrc` to LTS 24; Angular refuses Node 25 |

```bash
npm ci                                                      # respects the lockfile
npm run build                                               # both workspaces
npm test                                                    # unit suites
npm run test:integration:all --workspace @zanshin/backend   # four engines, needs Docker
```

## Before you change anything

**Read [`docs/architecture/`](docs/architecture/) first.** Documents 01 to 04 describe the
system as it is; the [decision register](docs/architecture/decisions/) says why, and what
was rejected. When a document and a module contradict each other, the module is right and
the document has a bug — say so rather than working around it.

**The layering is enforced, not suggested.** `backend/src/architecture.spec.ts` reads the
import graph: `domain ← scanning ← agent ← persistence ← repositories ← services ← api`. A
service writing SQL, or a domain file importing NestJS, fails the suite. The agent's
inability to import `typeorm`, `pg`, `mysql2` or `@nestjs/` is a **security property** —
see [decision 0003](docs/architecture/decisions/0003-long-polling-for-agents.md).

**Three traps that cause silent data loss**, each with a decision behind it:

- Anything entering an issue's **fingerprint** is a data contract. Changing a rule id, a
  finding type or a path normalization resolves every existing issue and recreates it,
  losing all triage — silently, across every target.
- An analyzer that fails returns **`null`, never `[]`**. An empty list means "ran, found
  nothing", which resolves the backlog
  ([0007](docs/architecture/decisions/0007-none-is-not-an-empty-list.md)).
- `synchronize` stays `false`. The schema belongs to the migrations, one set per dialect,
  and `schema-parity.integration-spec.ts` checks that the entities agree with them.

## Writing code here

**Comments explain why, not what.** This codebase's comments carry the reasoning — the
defect that motivated a guard, the alternative that was tried and failed, the cost being
accepted. Match that: a comment that restates the line below it is noise, a comment naming
the consequence of getting it wrong is why the next person does not break it.

**A guarantee that is not executed is not a guarantee.** Concurrency, dialect behaviour and
schema agreement are checked against real servers by the integration campaign, because each
of them has already produced a defect that was invisible on SQLite and to a careful
reading. Do not replace a running check with an assertion.

**Never skip silently.** There is no "skip if the database is missing" guard in the
integration suite, deliberately: a suite that skips itself reports green without checking
anything.
