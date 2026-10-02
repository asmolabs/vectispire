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
Run `npm run format -w vectispire-angular` before committing: CI checks formatting (Prettier, 120
columns) and fails on a file it would change. Never reformat files you do not otherwise touch.
`ng update` does not work in this workspace layout: bump versions by hand, install, then run
`npx ng update <pkg> --migrate-only --from=… --to=…` inside `vectispire-angular/`.

## What this codebase will not forgive

**One copy of each framework package.** A lockfile that holds two `@angular/core` — one hoisted at
the workspace root, one under `vectispire-angular/node_modules` — makes TypeScript see every Angular
type twice (`INPUT_SIGNAL_BRAND…@14374` vs `@15853`). After any dependency change, count copies of
`@angular/*`, `@openng/*` and `typescript` in `package-lock.json`; move Angular, Optimus UI and
TypeScript together, never one alone.

**TypeScript is pinned to one minor** (`~6.0.x`), because Angular 22 accepts only `>=6.0 <6.1`.

**Icons come from `@openng/icons`, never `primeicons`.** primeicons 8.x is under the PrimeUI licence
(revenue, headcount and licence key conditions); `@openng/icons` is the MIT fork of 7.0.0, same
classes. Read the licence of any version before raising it. `scripts/check-assets.mjs` refuses any `pi-*` class the installed stylesheet does not
define.

**The shell is Sparked** (`openng-org/sparked`, OpenNG's port of Sakai onto Optimus), its Tailwind
utilities `@openng/optimus-ui-tailwindcss`, never `tailwindcss-primeui`. Take from Sparked only its
upstream clean-ups; our i18n, menu, topbar and typing stay ours. `vectispire-angular/LICENSE.md` is the
template's MIT notice (copyright PrimeTek) and must stay: it was deleted once without anyone noticing.

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

**The application is zoneless.** Eager change detection renders after a template event, a signal
write or `markForCheck` — not after a `FileReader.onload`, a timer or a promise that only assigns a
plain field. State written from a callback is a signal.

**Errors are read with `messageOf`.** The server answers RFC 7807: the explanation is in `detail`,
and `err.error.message` is always empty, so fourteen screens showed the generic fallback.

**Every route has a `title` key** (`titles.*`), translated by `TranslatedTitleStrategy`; the
i18n check reads `app.routes.ts` and refuses a sentence as a title. **The shell is guarded**
(`signedIn` on the `''` parent): a new page under it needs no guard of its own for the session, and
a `returnUrl` is only ever used through `safeReturnUrl` — anything else is an open redirect.

**ESLint is type-aware** (`recommendedTypeChecked`, `no-deprecated`). Do not silence it with `any`;
and do not trust `eslint --fix` for `no-unnecessary-type-assertion`, which has removed assertions
the type-checker needed.

**An icon-only button has an accessible name** (`[ariaLabel]="'…' | translate"`): the template lint
checks native elements, not `<p-button>`; `scripts/check-icon-buttons.mjs`, run by `npm test`, covers
`<p-button>`, `<button>` and `<a pButton>` in every template and fails on one without a name. A plural
message is a `key_one`/`key_other` pair read with `t(key, { count })`, never "(s)" in the text.

**Translation keys are literal.** `'prefix.' + value | translate` and `` t(`…${x}`) `` are invisible
to the i18n check and ship a raw key when a new value appears; map a generated union to literal keys
(`Record<Union, 'a.b'>`) instead (decision 0019).

**A finding type has one list: `shared/finding-types.ts`.** Three screens spelt it, none alike — the
scan detail built `issues.types.${type}`, the issue detail translated `sast` alone — so a new type
(`plugin`, `imported`) shipped as a raw word on two of them. Add a type there, and to `FINDING_TYPES`
in `core/testing/contract.ts`.

**Plugin states are three, and two must never look alike** (decision 0017): `not_applicable` is not a
failure, `absent` is. A screen rendering both as an error puts a red row on every scan.

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

The unit-test DOM is **happy-dom** (jsdom 30 broke the download specs; the builder takes happy-dom
whenever it is installed, so do not add jsdom back beside it). Its gaps are the tests' to know:
canvas `getContext` returns `null`, so a chart renders nothing and a test about a chart reads its
data, not pixels; no stylesheet is applied, so `textContent` includes text the page hides (assert
the accessible name); an anchor `click()` calls `window.open(href, '_self')`, which is why the
download specs replace `HTMLAnchorElement.prototype.click`. `URL.createObjectURL` accepts its
`Blob`, and `checkValidity`/`validity` and `matchMedia` are real: do not polyfill them. An error
thrown inside an `HttpTestingController.flush` subscriber is not a failed test but an "Unhandled
Error" that turns the run red: read the summary, not only the pass count.

The Playwright suite needs a running control plane; reproduce the `e2e` job of
`.github/workflows/ci.yml`: a `mysql:9.4` container, the boot jar against it with `ddl-auto` left at
`validate`, and `VECTISPIRE_DB_URL`/`_USER`/`_PASSWORD` exported to Playwright too — the helpers in
`e2e/support/fixture.ts` reset the login throttle and seed a finding through `mysql2` with the
control plane's own variables (decision 0034). A negative assertion straight after a save
(`not.toHaveText('Ready')`) holds while the request is still in flight: wait for what the save's
answer changes (its form closing) before the next click, or the answer lands on the next form — on
SQLite this raced and won, on MySQL it lost every time.
A `p-multiselect`'s `inputId` lands on a hidden input: Playwright times out clicking it — click the
`p-multiselect` that has it (`page.locator('p-multiselect', { has: page.locator('#id') })`). The
screenshot campaign (`screens-en`, `screens-fr` projects) regenerates `docs-site/assets/screens/`;
commit regenerated screenshots in a commit of their own so the visual diff can be reviewed.

**Never report a green build when it is red.** Run it, read the output, say what it says.
