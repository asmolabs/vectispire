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

Compile (with `-Werror` — a dangling doc comment fails it), unit, architecture and HTTP suites.
`ArchitectureTest` rejects repository access outside services, transactions and audit writes in a
controller (`core.api` or a module's `web`) outside `core.access.web.security`, a class in no module
place, and a module reaching into another module's internals (decision 0028).

## 3. Front end — on Node 24

```bash
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; nvm use
npm ci && npm run lint && npm run format:check -w vectispire-angular && npm run build && npm test
```

From the repository root. `npm test` includes the asset check, the i18n ratchets, the dead-API-method
check and Vitest. After a dependency change, also confirm one copy of each `@angular/*`, `@openng/*`
and `typescript` in `package-lock.json`, and `npm audit`.

## 4. Engine campaign — when engine-sensitive files changed

Migrations, `core/repositories/`, `core/persistence/`, `core/config/`, `src/integrationTest/`,
`gradle/libs.versions.toml`, `gradle.lockfile`:

```bash
cd vectispire-java && ./gradlew integrationTestAll
```

MySQL, PostgreSQL (Testcontainers, needs Docker) and the SQLite fixture. A migration is written once
under `db/migration/common` with the type placeholders when only the types differ, or three times,
one per dialect, when the structure does (decision 0027); `MigrationLayoutTest` in `./gradlew build`
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

A behaviour change updates `docs-site/` and `docs/{en,fr}/` **in both languages**. If `docs-site/` or
`mkdocs.yml` changed, build the site strictly with the hash-pinned requirements
(`pip install --require-hashes --no-deps -r ci/docs/requirements.txt`, Python 3.12+, `mkdocs build
--strict`).

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
- Push `develop`. **`main` only moves by fast-forward to a commit whose `ci.yml` run is green**
  (`gh run list --commit <sha> --workflow ci.yml`), and it requires linear history. Merging a pull
  request that changes `.github/workflows/` needs the `workflow` scope the `gh` token lacks:
  cherry-pick and push over SSH instead.
- **Stop a pending main watcher when a hole is found in the commit it waits on.** A watcher that
  fast-forwards `main` on green does not know the commit is wrong; stop it, push the fix, and watch
  the fixed commit instead.
- The nightly (`nightly.yml`, from `main`) is the only place every suite runs unconditionally. Do not
  cut a release on a nightly that has not been green.
