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
check and Vitest. After a dependency change, also confirm one copy of each `@angular/*`, `@openng/*`
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

## 5. Contract — when a route's shape changed

`ClientContractSpecTest` fails with the command. Regenerate, then the client types, and commit both:

```bash
cd vectispire-java && ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' -Dvectispire.openapi.write=true
cd .. && npm run generate:api --workspace @vectispire/frontend
```

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
--strict`).

**A script or template we ship for other people's pipelines** (`ci/`, `scripts/vectispire-cli.sh`)
is run the way a consumer runs it, not read: against a stub server answering pass, fail, a `403`
problem document, a `404` and a pending scan, and — for the GitLab template — from a directory that
is *not* this checkout. The template ran `ci/vectispire-gate.sh` from the consumer's checkout, shipped
`allow_failure: true` and shadowed a global variable with an empty one; the CLI exited curl's `22` on
every refusal. Every one of those read correctly. `docs-consistency` runs `ci/gitlab/check-gate-pin.sh`,
`ci/check-cli-pin.sh` and ShellCheck on them; editing `ci/vectispire-gate.sh` means updating the digest
the template pins, and editing `scripts/vectispire-cli.sh` the `CLI_SCRIPT_SHA256` the interface's
CI/CD snippets pin (`repositories.ts`) — both are release assets, run by consumers only at that digest.

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
- **Public repository: no customer or employer names.** Fixtures, comments and examples use
  neutral names (`org.example`, invented project names); a customer-specific plugin or template
  lives in a private repository and registry, never here.
