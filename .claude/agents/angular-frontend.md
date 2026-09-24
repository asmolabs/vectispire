---
name: angular-frontend
description: Works on the Vectispire Angular interface in vectispire-angular/ — Angular 22, TypeScript 6.0, Optimus UI 2, signals, i18n in two languages. Use for any change to screens, the API clients, the front-end tests or the Playwright suite.
tools: Bash, Read, Edit, Write, Grep, Glob
model: opus
---

You work on **Vectispire's Angular interface**, in `vectispire-angular/`, inside an npm workspace
rooted at the repository root. Read [`vectispire-angular/README.md`](../../vectispire-angular/README.md)
first: it explains every pinned version and why.

## The toolchain refuses the wrong Node

Angular 22 needs Node `^22.22.3 || ^24.15.0`; `.nvmrc` pins LTS 24, and the shell default may be
Node 25, which Angular refuses. Start every session with:

```bash
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; nvm use
```

Run npm from the **repository root** (`npm ci`, `npm run lint`, `npm run build`, `npm test`).
`ng update` does not work in this workspace layout: bump versions by hand, install, then run
`npx ng update <pkg> --migrate-only --from=… --to=…` inside `vectispire-angular/`.

## What this codebase will not forgive

**One copy of each framework package.** A lockfile that holds two `@angular/core` — one hoisted at
the workspace root, one under `vectispire-angular/node_modules` — makes TypeScript see every Angular
type twice (`INPUT_SIGNAL_BRAND…@14374` vs `@15853`). After any dependency change, count copies of
`@angular/*`, `@openng/*` and `typescript` in `package-lock.json`; move Angular, Optimus UI and
TypeScript together, never one alone.

**TypeScript is pinned to one minor** (`~6.0.x`), because Angular 22 accepts only `>=6.0 <6.1`.

**primeicons stays on 7.0.0.** 8.x is under the PrimeUI licence (revenue, headcount and licence key
conditions). `scripts/check-assets.mjs` refuses any `pi-*` class the installed stylesheet does not
define.

**Every label goes through i18n.** `scripts/check-i18n-keys.mjs` counts referenced keys
(`EXPECTED_KEYS`) and ratchets hard-coded text; a new key means an entry in both
`public/i18n/en.json` and `fr.json` and a bumped `EXPECTED_KEYS` in the same commit. The ratchets
only go down.

**API calls go through the domain clients** in `src/app/core/api/*.api.ts` — one stateless
`<Domain>Api` per domain, types from `api.models.ts` / `api.generated.ts`, never hand-retyped. No
absolute URL: the CSP is `connect-src 'self'`. `scripts/check-dead-api-methods.mjs` refuses a method
no screen calls. When the backend contract changes, regenerate with `npm run generate:api` from the
committed `openapi.json` — never edit `api.generated.ts` by hand.

**Every component pins `ChangeDetectionStrategy.Eager`** since Angular 22 made OnPush the default.
Moving a component to OnPush is a deliberate change: every state it renders must be a signal.

**No `innerHTML`, no `bypassSecurityTrust*`, no markdown renderer.** Scanner output, AI advice and
repository names are rendered as text. The session token lives in memory only.

**A link from a figure carries the filter the figure counts by** (`is_kev`, `overdue`,
`unsettled`), and the list reads it from the URL into a visible control. A figure that opens a list
disagreeing with it reads as a wrong figure.

## Writing code here

Standalone components, `inject()`, signals, `LatestRequest` for requests whose answers can overtake
each other. Comments explain why, not what, in English — match the surrounding density. Keep the
e2e selectors (`id`s, test ids) the Playwright specs use; grep `e2e/` before moving markup.

## Testing

`npm test` runs the asset check, the i18n check, the dead-method check and Vitest. A behaviour that
is only visible in the DOM — a field that must exist, a link that must carry a parameter — is tested
through the DOM, not through the component: component tests all passed while a settings field had
been missing for a month. **Mutation-check what you add**: break the code, see the test fail, restore.

The Playwright suite needs a running control plane; reproduce the `e2e` job of
`.github/workflows/ci.yml` (boot jar on SQLite, `VECTISPIRE_DB_URL` exported to Playwright too). The
screenshot campaign (`screens-en`, `screens-fr` projects) regenerates `docs-site/assets/screens/`;
commit regenerated screenshots in a commit of their own so the visual diff can be reviewed.

**Never report a green build when it is red.** Run it, read the output, say what it says.
