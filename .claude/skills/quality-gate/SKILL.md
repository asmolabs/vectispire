---
name: quality-gate
description: The checks a Vectispire change passes before it is committed and pushed — backend build, front-end lint/build/tests on Node 24, doc checks, engine campaign when engine-sensitive files changed, contract regeneration, mutation check of new tests — and the develop → CI → main flow. Use before committing or pushing any change, or when asked to verify a change.
---

# Quality gate

Run what applies to the change, **read the output**, and report what it says — never a green you did
not see. Stop at the first red and fix it; do not push around it.

## 1. What changed

```bash
git status --short && git diff --stat
```

Classify the change: backend (`vectispire-java/`), front end (`vectispire-angular/`, `package*.json`),
engine-sensitive (see step 4), contract (a route's request or response shape), docs, workflows.

## 2. Backend

```bash
cd vectispire-java && ./gradlew build
```

Compile (with `-Werror` — a dangling doc comment fails it), unit, architecture and HTTP suites —
the last two on MySQL (decision 0034): a Testcontainers container, so Docker must be running, or the
server `VECTISPIRE_TEST_DB_URL` names; without either they fail, and that is not a flake. With
`testcontainers.reuse.enable=true` on the machine, the container is `vectispire-test-mysql`, kept
across runs and worktrees (`vectispire-java/README.md`, "One MySQL kept across runs").
`ModularityTest` runs Spring Modulith's `verify()` (decision 0030): a cycle between modules, a reach
into another module's internals, or a dependency the module's `package-info` does not list fails the
build, and so does a module without a list or a line nothing uses. Its message names the edge; the
answer is the owner's API or a port, and a new line in a list is the review's decision, with its reason
beside it. `ArchitectureTest` rejects, inside a module, repository access outside services,
transactions and audit writes in a module's `web` outside `core.access.web.security`, a class in no
module place, and `access` used by the services of a module that uses it for its routes only.
`CrossModuleQueriesTest` rejects a query string naming another module's table that its list does not
carry.

**Dependency verification** fails the build on any artifact `gradle/verification-metadata.xml` does
not vouch for — signed by a key in `gradle/verification-keyring.keys` trusted for its group, or
matching a recorded sha256. When the change adds or bumps a dependency or a plugin — a Dependabot
Gradle pull request included, since Dependabot updates the version and not the metadata:

```bash
cd vectispire-java && ./gradle/update-verification-metadata.sh
git diff -- gradle/verification-metadata.xml gradle/verification-keyring.keys
```

The script regenerates in a fresh Gradle home over every task CI runs, and fails when a key cannot
be downloaded rather than falling back to a checksum. **Then review what it added before committing
it** — this is the one step where trust is extended: a new `<trusted-key>` must belong to the group's
publisher (the keyring carries its uid when the key server served one, `keyserver.ubuntu.com`
otherwise; compare the fingerprint with the one the project publishes),
a new `<sha256>` is an unsigned artifact pinned as downloaded. For a Dependabot pull request, check out
its branch, run the script, review, and push the result to that branch yourself. **There is no
workflow that does it for the bot, deliberately**: it would re-trust whatever the pull request
resolves, which is the attack verification exists to stop, and it would need a token that writes to
the branch in the job running the pull request's Gradle code — the combination `release.yml` was split
into two jobs to avoid. Never answer a verification failure with `--dependency-verification=lenient`,
`org.gradle.dependency.verification`, `<trusted-artifacts>` or a wider `<trusted-key>`: CI's `jvm` job
passes `--dependency-verification=strict` and fails when the metadata file is missing.

## 3. Front end — on Node 24

```bash
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; nvm use
npm ci && npm run lint && npm run format:check -w vectispire-angular && npm run build && npm test
```

From the repository root. `npm test` includes the asset check, the i18n ratchets, the dead-API-method
check and Vitest, then the test floor (`scripts/check-test-floor.mjs`): a spec file absent from the
run, or running fewer tests than it declares, fails — once a run reported 52 tests fewer, every file
green. After a dependency change, also confirm one copy of each `@angular/*`, `@openng/*`
and `typescript` in `package-lock.json`, and `npm audit`.

## 4. Engine campaign — when engine-sensitive files changed

Migrations, any `core/<module>/persistence/`, `core/config/`, `src/integrationTest/`,
`gradle/libs.versions.toml`, `gradle.lockfile`, `gradle/verification-metadata.xml`,
`gradle/verification-keyring.keys`:

```bash
cd vectispire-java && ./gradlew integrationTestAll
```

MySQL and PostgreSQL (Testcontainers, needs Docker). A migration is written once under
`db/migration/common` with the type placeholders when only the types differ, or twice, one per
dialect, when the structure does (decisions 0027, 0034); `MigrationLayoutTest` in `./gradlew build`
refuses anything in between.

**A migration that rewrites existing rows** — a backfill, a new default stamped on old targets — is
also run the way an installation meets it: on a database the last release has written to.

```bash
docker build -f Dockerfile -t vectispire:latest . && ENGINE=mysql scripts/upgrade-drill.sh
```

(`ENGINE=postgresql` too; the nightly's `upgrade` job runs both.) A field it reads back changed on
purpose goes into `ci/upgrade/accepted-rewrites.txt` with the migration and the reason, in the
migration's commit, or the nightly stays red until the next tag. On an arm64
machine the release image runs emulated: about a minute and a half per engine. The drill verifies
the release image's signature with cosign before pulling it and stops if that fails — it needs
the network to ghcr.io and Sigstore, and there is no switch to skip it; `FROM_IMAGE` must be a
digest and comes with its `FROM_TAG`.

## 4b. Rust port — when `vectispire-rust/` changed

```bash
cd vectispire-rust && ./check.sh
```

The toolchain is `rust-toolchain.toml`'s. Docker is required: the clone and container suites start
throwaway `vs-rs-*` containers and fail without a daemon — never skip them. `check.sh` runs fmt, clippy
with `-D warnings` (and the lints `Cargo.toml` denies), the tests, `cargo deny`, `security/check-unsafe.sh`,
`security/lint-ceilings.sh`, `cargo vet --locked` and `security/semgrep.sh`; CI's `rust` job runs the same
steps (`vectispire-rust/security/README.md` lists what each refuses).

**A new dependency is reviewed in three places in the same diff**: its licence in `deny.toml` if it is
new, its build script in `[bans.build]` if it has one (with what it builds), and an audit or a named
exemption in `supply-chain/` (`cargo vet` says which is missing). Never `cargo vet regenerate
exemptions` to make a red run green without reading what it adds. A parser of untrusted input gets a
fuzz target in `fuzz/` (`fuzz/run.sh 60 <target>` runs it). A ceiling in `security/lint-ceilings.txt` is
lowered when a use goes away, never raised.

When the image changed: `security/reproducible-image.sh linux/arm64` (or `linux/amd64`, as CI) must say
`reproducible`.

**The control plane's crates (`cp-*`, `migrate`) are held to the Java side by suites `check.sh` does not run**,
because they need a JDK 25 and Gradle beside Docker; CI's `rust` and `rust-replay` jobs run them, and so should
you when you touch those crates or a Flyway migration:

```bash
cd vectispire-rust
./crates/migrate/oracle/check-oracle.sh             # the migration runner against the real Flyway, both engines
./crates/cp-db/scripts/sqlx-prepare.sh check        # the checked queries' caches are current (both engines)
crates/cp-contract/scripts/record-goldens.sh /tmp/vs-recordings    # the Java suite's traffic, recorded
cargo run -p vectispire-cp-contract -- replay-plan /tmp/vs-recordings
```

A route ported to the control plane leaves `crates/cp-contract/reference/not-yet-ported.txt` (the list, and its
ceiling, only shrink) in the same commit — and its recordings are then owed a replay, which `replay-plan` refuses
to let pass (exit 3). `cp-arch-tests` holds the module edges, the layers, `unsafe`, the agent's isolation and the
route-authorization rules; a new module crate adds its edges to `crates/cp-arch-tests/data/edges.toml` with their
reason.

## 5. Contract — when a route's shape changed

`ClientContractSpecTest` fails with the command. Regenerate, then the client types, and commit both:

```bash
cd vectispire-java && ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' -Dvectispire.openapi.write=true
cd .. && npm run generate:api --workspace @vectispire/frontend
```

Read the regenerated diff for `operationId` lines that moved on routes you did not touch: a new handler
method named like an existing one renumbers springdoc's suffixes. `PublishedOperationIdsTest` fails on
it; the answer is `@Operation(operationId = …)` on the new route, never an edit of
`published-operation-ids.txt` (decision 0043, §1).

Then compare the contract with the last release, as CI's `api-compat` does:

```bash
ci/openapi/compat.sh
```

It fails on a change that breaks a client of the last `v*` tag — a removed route, operation,
`operationId` or response field, a request field made required, a narrowed request enum, a changed
type. The answer is the additive form (a new field beside the old one, the old one `deprecated`),
not a regeneration. A break that cannot wait goes into `ci/openapi/accepted-breaks.txt` with its
reason, in the same commit, and into the release notes; a line for an older tag or for a break that
no longer happens fails the run, so the list is empty again at each release.

## 6. Docs — when docs, README or AGENTS changed, and whenever behaviour did

```bash
python3 scripts/check-doc-links.py && python3 scripts/check-doc-facts.py
```

**The REST reference is also checked by the backend build.** `ApiReferenceTest` reads the route
column of `docs/{en,fr}/api/rest_api_reference.md` and fails on a path the API does not answer — a
query string in that column (`/coverage-imports?format=`) is such a path; name parameters in the
description instead. A reference edited after `./gradlew build` ran has not been checked: run
`./gradlew :vectispire-core:test --tests '*ApiReferenceTest*'` again. On 2026-09-28 it was the one red
of a push whose every other check had run green locally.

A behaviour change updates `docs-site/` and `docs/{en,fr}/` **in both languages**. If `docs-site/` or
`mkdocs.yml` changed, build the site strictly with the hash-pinned requirements
(`pip install --require-hashes --no-deps -r ci/docs/requirements.txt`, Python 3.12+, `mkdocs build
--strict`). `check-doc-links.py` does **not** replace it: it checks that a linked file exists, not that
its `#anchor` does. On 2026-10-12 a shell redirection in inline code (`` `… </dev/null` ``) was read
by Python-Markdown as a raw HTML tag and swallowed every heading after it on the page; the links
checker was green, the strict build of the `docs` workflow failed on six vanished anchors. Write
`< /dev/null`, or put such a command in a fenced block.

**A script or template we ship for other people's pipelines** (`ci/`, `scripts/vectispire-cli.sh`)
is run the way a consumer runs it, not read: against a stub server answering pass, fail, a `403`
problem document, a `404` and a pending scan, and — for the GitLab template — from a directory that
is *not* this checkout. The template ran `ci/vectispire-gate.sh` from the consumer's checkout, shipped
`allow_failure: true` and shadowed a global variable with an empty one; the CLI exited curl's `22` on
every refusal. Every one of those read correctly. `docs-consistency` runs `ci/gitlab/check-gate-pin.sh`,
`ci/check-cli-pin.sh` and ShellCheck on them; editing `ci/vectispire-gate.sh` means updating the digest
the template pins, and editing `scripts/vectispire-cli.sh` the `CLI_SCRIPT_SHA256` the interface's
CI/CD snippets pin (`repositories.ts`) — both are release assets, run by consumers only at that digest.

**Running the shipped composition to test a change** (a healthcheck, a service's command): a project
name does **not** isolate it. `docker-compose.yml` gives its volumes and networks fixed `name:`s, so
`docker compose -p anything up db` attaches to the operator's real `vectispire_mysql_data` — on
2026-10-09 a second mysqld started on a developer's live database volume for ten seconds before
anyone noticed. Bring a service up only through an override that replaces every named volume with a
throwaway one (and `down -v` after), or read `docker volume ls` first and refuse if the names
exist.

## 7. Mutation check — for every test added

Break the code the test pins (remove the guard, flip the condition), run the test, confirm it
**fails**, restore the file, confirm it passes. Back the file up first and compare after restoring.
Report which mutations were caught. A test that stays green without its guard pins nothing.

Script it with a `try/finally` that writes the original back and a timeout on each run: a regex
mutant once ran for fifteen minutes, the run was killed, and the source stayed mutated.

## 8. Commit and push

- One commit per logical change, message in the repository's style (`fix(area): …`, body saying what
  was wrong, what changed and how it was verified), ending with the attribution line the session
  requires.
- The repository is public: a commit fixing a vulnerability says what is fixed, not how to exploit
  the unfixed version.
- **Wait for every check run on the commit, not the workflow's status.** The `main` ruleset requires `e2e`, which can still be running when `gh run list` already reports the `ci.yml` run completed; a push then is refused. Poll `gh api repos/asmolabs/vectispire/commits/<sha>/check-runs` until none is pending and none failed.
- Push `develop`. **`main` only moves by fast-forward to a commit whose `ci.yml` run is green**
  (`gh run list --commit <sha> --workflow ci.yml`), and it requires linear history. Merging a pull
  request that changes `.github/workflows/` needs the `workflow` scope the `gh` token lacks:
  cherry-pick and push over SSH instead.
- **Stop a pending main watcher when a hole is found in the commit it waits on.** A watcher that
  fast-forwards `main` on green does not know the commit is wrong; stop it, push the fix, and watch
  the fixed commit instead.
- The nightly (`nightly.yml`, from `main`) is the only place every suite runs unconditionally. Do not
  cut a release on a nightly that has not been green.
- **A green check is only worth what it read.** The `secrets` job scanned 0 commits for six weeks:
  in its container git refused the checkout ("dubious ownership"), gitleaks logged it, said
  `no leaks found` and exited 0. When you add or change a CI job that runs a scanner in a
  container, read its log once for the count of what it examined, and make the job refuse a run
  that examined nothing.
- **A check is run on what it must refuse, not only on the tree it passes.** The digest-pin step of
  `dockerfile-policy` was green on every Dockerfile here and accepted `FROM node:24 AS node` — it
  registered the line's own stage name before testing the image against the stage names — and a
  digest of one hex digit. Before trusting a policy step, run its very text (extracted from the
  workflow) on fixtures it must refuse and on ones it must pass, under the runner's tools (`mawk` on
  `ubuntu-latest`, not the macOS `awk`).
- **A test that plants a secret-shaped value fails `secrets`** once it is pushed (R1's
  `AKIA…` fixture did). Mark the line with a trailing `// gitleaks:allow` comment, which gitleaks
  honours, and say in the comment beside it that the value is invented; a fingerprint in
  `.gitleaksignore` can only be written after the commit exists, which costs a red pipeline first.
- **Documentation trips `secrets` too.** A table of control codes beside numbers
  (`NIS2-ART21-CRYPTO` … `| 60 |`) reads as a `generic-api-key` to gitleaks, and the job went red
  on 2026-10-09 for two pushes before anyone looked. Before pushing a docs change of that shape,
  run gitleaks on a clone (`git clone -q . /tmp/gl && docker run --rm -v /tmp/gl:/repo -w /repo
  --entrypoint sh <the image ci.yml pins> -c 'git config --global --add safe.directory /repo;
  gitleaks detect --source=. --config .gitleaks.toml'` — a worktree's `.git` is a file, so mounting
  the worktree itself scans nothing), and pin a false positive in `.gitleaksignore` with its reason.
- **Public repository: no customer or employer names.** Fixtures, comments and examples use
  neutral names (`org.example`, invented project names); a customer-specific plugin or template
  lives in a private repository and registry, never here.
