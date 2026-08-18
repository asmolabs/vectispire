# Agents

Zanshin is a **NestJS + Angular** application in a single npm workspace, and there is now a
complete **Spring Boot 4 / JDK 25** port of the backend in [`zanshin/`](zanshin/) alongside it.

Which one you touch depends on what you are doing. **New backend work goes in `zanshin/`** —
it is the implementation of record. `backend/` is kept as the reference to compare a surprise
against until somebody has run the JVM one against a real deployment; it is not being extended.
The Angular frontend is unchanged and talks to whichever backend is running, because the HTTP
contract is the same.

Read [`zanshin/README.md`](zanshin/README.md) before working there. It carries the module
graph, what each guarantee is enforced by, and — the part that matters most — the index of
where the port deliberately does something *different* from the TypeScript, and why.

It was ported from Python/Reflex before that; the Python tree is gone. If you find instructions
telling you to install Reflex skills, set up a virtualenv, or run `reflex init`, they are stale
— this file used to contain exactly that.

## The stack

| | |
|---|---|
| Backend | NestJS 11, TypeORM, `backend/` — see [`backend/README.md`](backend/README.md) |
| Frontend | Angular 21, Optimus UI, `frontend/` — see [`frontend/README.md`](frontend/README.md) |
| Database | PostgreSQL (default), MySQL, MariaDB, SQLite — one migration set each |
| Node | pinned by `.nvmrc` to LTS 24; Angular refuses Node 25 |
| JVM backend | Spring Boot 4.1, JDK 25, Gradle, `zanshin/` — see [`zanshin/README.md`](zanshin/README.md) |

```bash
npm ci                                                      # respects the lockfile
npm run build                                               # both workspaces
npm test                                                    # unit suites
npm run test:integration:all --workspace @zanshin/backend   # four engines, needs Docker

cd zanshin && ./gradlew build                               # the JVM port: compile + tests
cd zanshin && ./gradlew integrationTestAll                  # four engines, needs Docker
```

## Before you change anything

**Read [`docs/architecture/`](docs/architecture/) first.** Documents 01 to 04 describe the
system as it is; the [decision register](docs/architecture/decisions/) says why, and what
was rejected. When a document and a module contradict each other, the module is right and
the document has a bug — say so rather than working around it.

**The layering is enforced, not suggested**, on both sides.
`backend/src/architecture.spec.ts` reads the import graph, and `zanshin`'s
`ArchitectureTest` does the same with ArchUnit — except for the agent's isolation, which in the
JVM tree is a fact about the module graph rather than a rule: `zanshin-agent` does not depend
on `zanshin-core`, so the violation fails to compile instead of failing review. The graph: `domain ← scanning ← agent ← persistence ← repositories ← services ← api`. A
service writing SQL, or a domain file importing NestJS, fails the suite. The agent's
inability to import `typeorm`, `pg`, `mysql2` or `@nestjs/` is a **security property** —
see [decision 0003](docs/architecture/decisions/0003-long-polling-for-agents.md).

**Three traps that cause silent data loss**, each with a decision behind it, and each true in
both trees:

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
