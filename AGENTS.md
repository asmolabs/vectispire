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
| Database | MySQL (default), PostgreSQL — Flyway migrations (`db/migration/{vendor}`). SQLite is the test fixture, not a deployment ([0014](docs/architecture/en/decisions/0014-two-engines-and-a-test-fixture.md)) |
| Node | pinned by `.nvmrc` to LTS 24; Angular refuses Node 25 |

```bash
cd vectispire-java && ./gradlew build                # compile, unit, architecture and HTTP suites
cd vectispire-java && ./gradlew integrationTestAll   # PostgreSQL, MySQL, SQLite fixture

npm ci                                            # respects the lockfile
npm run build                                     # the Angular interface
npm test
```

**CI is [`.gitlab-ci.yml`](.gitlab-ci.yml), and `.github/workflows/` is a fossil.** The only
remote is GitLab, which does not execute GitHub Actions, so for most of this project's life
*nothing had ever been verified by a machine* — the workflows are kept as a record of what the
checks were, and they are not what runs. If you add a check, add it to `.gitlab-ci.yml` or it
will not happen.

On every push, `verify` runs `secrets`, `links`, `c4-drift`, `jvm` (`./gradlew build`),
`frontend` (`npm ci && npm run build && npm test`), `sbom`, `vulnerabilities` and `npm-audit`;
then `package` runs `images`, which builds both images with Jib **and starts the control plane
against a real MySQL** before believing them. Syft and Grype are digest-pinned to what
`ScannerImages` pins, so the same scanner version audits Vectispire as audits its targets.

**`integrationTestAll` is in CI, but only nightly** — the `databases` job, 40 minutes, gated on
`$CI_PIPELINE_SOURCE == "schedule"`, alongside `dockerfiles` and the Playwright `e2e` suite.
Declaring a nightly job does not schedule it: the schedule has to exist in the project's CI/CD
settings, and until it does these three have never run. **A green pipeline therefore does not
mean portability or the browser paths were checked.** Run the campaign by hand before a release.

A **`v*` tag** runs the `release` job: `./gradlew build`, then the jar signed with Sigstore
keyless. It **verifies the signature it just made** before publishing anything, with the same
command a consumer runs — a signature nobody has checked is a signature that does not work. The
certificate identity is `${CI_PROJECT_URL}//.gitlab-ci.yml@refs/tags/${CI_COMMIT_TAG}` with
issuer `https://gitlab.com`; both change if the file is renamed.

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

**Four traps**, each with a decision or an executable rule behind it. The first leaks other
accounts' data; the rest lose your own:

- **A role marker is not authorization**, and this is the mistake made most often here.
  `@RequiresAccount` proves the caller is signed in; it says nothing about *whose* estate the
  response describes. Twenty-three routes carried a marker, passed `RouteAuthorizationTest`,
  and served other accounts' repositories, containers and findings. A route naming a target
  must resolve a `Visibility` — `VisibilityService.of(user, credentialRestriction)`, the
  account's grant intersected with the credential's — and pass it to the query, or refuse
  through `Visibilities.requireVisible(...)`, which answers **404 and never 403**: a refusal
  has to be indistinguishable from an absence, or it confirms the thing exists.
  `AuthorizationCoverageTest` is the rule that catches the omission, because four manual sweeps
  did not converge — the twenty-first hole appeared hours after the twentieth was closed.
- Anything entering an issue's **fingerprint** is a data contract. Changing a rule id, a
  finding type or a path normalization resolves every existing issue and recreates it,
  losing all triage — silently, across every target.
- An analyzer that fails returns **absent, never empty**. `ScanArtifacts` uses `Optional`
  fields for exactly this: an empty list means "ran, found nothing", which resolves the
  backlog ([0007](docs/architecture/en/decisions/0007-none-is-not-an-empty-list.md)). The same
  rule decides a scan's status — every step absent and something broken means the target was
  never examined, and `completed` would say the opposite.
- **`ddl-auto` stays `validate`.** The schema belongs to the Flyway migrations, written by
  hand *per dialect* under `db/migration/{postgresql,mysql,sqlite}/` — a migration is written
  three times, and forgetting one is a startup failure on that engine only.
  `SchemaParityIntegrationTest` checks on every engine the campaign runs that the entities agree
  with it.
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

