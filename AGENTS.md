# Agents

Vectispire is a **Spring Boot 4 / JDK 25** control plane in [`vectispire-java/`](vectispire-java/) with an
**Angular 21** interface in [`vectispire-angular/`](vectispire-angular/). They talk over HTTP and are
built by different toolchains: Gradle for the backend, npm for the frontend.

Read [`vectispire-java/README.md`](vectispire-java/README.md) before working there. It carries the
module graph, what each guarantee is enforced by, and the index of the defects that were fixed
rather than reproduced.

## The stack

| | |
|---|---|
| Backend | Spring Boot 4.1, JDK 25, Gradle, `vectispire-java/` — see [`vectispire-java/README.md`](vectispire-java/README.md) |
| Frontend | Angular 21, Optimus UI, `vectispire-angular/` — see [`vectispire-angular/README.md`](vectispire-angular/README.md) |
| Database | MySQL (default), PostgreSQL, MariaDB, SQLite — Flyway migrations (`db/migration/{vendor}`) |
| Node | pinned by `.nvmrc` to LTS 24; Angular refuses Node 25 |

```bash
cd vectispire-java && ./gradlew build                # compile, unit, architecture and HTTP suites
cd vectispire-java && ./gradlew integrationTestAll   # four engines, needs Docker

npm ci                                            # respects the lockfile
npm run build                                     # the Angular interface
npm test
```

**CI runs the first, third, fourth and fifth of those, and not the second.** The four-engine
campaign needs Docker and ten minutes; it is run by hand before a release. A green tick does not
mean portability was checked.

CI also runs a **`supply-chain`** job that no local command mirrors: Syft builds an SBOM of the
jar that ships and Grype fails on a fixable High finding, and `npm audit` blocks on production
dependencies. It uses the scanner digests `ScannerImages` pins, so the same scanner version
audits Vectispire as audits its targets.

A **`v*` tag** runs [`release.yml`](.github/workflows/release.yml): the suites on the tagged tree,
then the jar and its SBOM signed with Sigstore keyless and published. It **verifies the signature
it just made** before uploading anything, with the same command a consumer runs — a signature
nobody has checked is a signature that does not work. `workflow_dispatch` exercises the whole path
and publishes nothing.

## Before you change anything

**Read [`docs/architecture/`](docs/architecture/) first.** Documents 01 to 04 describe the
system as it is; the [decision register](docs/architecture/en/decisions/) says why, and what
was rejected. When a document and a module contradict each other, the module is right and
the document has a bug — say so rather than working around it.

**The layering is enforced, not suggested.** `ArchitectureTest` reads the import graph with
ArchUnit: `domain ← scanning ← persistence ← repositories ← services ← api`. A service writing
SQL, or a domain class importing Spring, fails the suite.

**The agent's isolation is not one of those rules — it is a fact about the build graph.**
`vectispire-agent` does not depend on `vectispire-core`, so no JDBC driver is on its compile
classpath and the violation fails to compile rather than failing review. That is a **security
property**: an agent holding a database connection would also need `ENCRYPTION_KEY`, which
decrypts every deployment key Vectispire stores — see
[decision 0003](docs/architecture/en/decisions/0003-long-polling-for-agents.md).

**Three traps that cause silent data loss**, each with a decision behind it:

- Anything entering an issue's **fingerprint** is a data contract. Changing a rule id, a
  finding type or a path normalization resolves every existing issue and recreates it,
  losing all triage — silently, across every target.
- An analyzer that fails returns **absent, never empty**. `ScanArtifacts` uses `Optional`
  fields for exactly this: an empty list means "ran, found nothing", which resolves the
  backlog ([0007](docs/architecture/en/decisions/0007-none-is-not-an-empty-list.md)). The same
  rule decides a scan's status — every step absent and something broken means the target was
  never examined, and `completed` would say the opposite.
- **`ddl-auto` stays `validate`.** The schema belongs to the Flyway migrations, and
  `SchemaParityIntegrationTest` checks on four engines that the entities agree with it.
  Letting Hibernate reconcile the schema would mean two authorities for one schema, and the
  one that runs second wins silently.

## Writing code here

**Comments explain why, not what.** This codebase's comments carry the reasoning — the
defect that motivated a guard, the alternative that was tried and failed, the cost being
accepted. Match that: a comment that restates the line below it is noise, a comment naming
the consequence of getting it wrong is why the next person does not break it.

**A guarantee that is not executed is not a guarantee.** Concurrency, dialect behaviour and
schema agreement are checked against real servers by `integrationTestAll`, because each of
them has already produced a defect that was invisible on SQLite and to a careful reading. Do
not replace a running check with an assertion.

**And a wiring that is not exercised is not wired.** The built-in worker claimed nothing for
as long as it existed, because no bean supplied its `ScanRunner` and the dispatcher's
`Optional` was empty; every queued scan stayed `pending`, silently, on an install whose own
defaults say the worker is on. No unit test could see it. Start the application.

It has happened twice. `IssueTriageService.expireStale` was called by **nothing** — its own
javadoc said "called from the maintenance tick", and that sentence was the only place the claim
existed. An acceptance recorded "for thirty days" kept its review date, exported it into SARIF as
"to review on …", and never came back. Every service involved had passing tests, because no test
of a service can see that its caller is missing. `MaintenanceJobsTest` now asserts the
composition itself, which is the only level at which that class of defect is visible.

**Never skip silently.** There is no "skip if the database is missing" guard in the
integration suite, deliberately: a suite that skips itself reports green without checking
anything.

**Documentation stays in sync across languages.** Whenever regulatory frameworks, security
roles, VEX/CSAF formats, triage workflows, or API contracts evolve, update both `docs/fr/` and
`docs/en/` simultaneously. A feature without documentation is invisible to auditors and teams.

