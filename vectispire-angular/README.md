# Vectispire — Angular UI

Vectispire's user interface: the screens over the HTTP API that
[`vectispire-java/`](../vectispire-java/) serves.

```bash
npm start                 # from the root, serves on http://localhost:4280
npm run build
npm run lint              # ESLint, type-aware, over src/ and the Playwright suite; then tsc over the suite
npm run format            # Prettier at 120 columns; CI runs `format:check` and fails on unformatted code
npm test                  # asset, i18n, dead-API, icon-button and spec-type checks, then the Vitest suite and its test floor
```

The dev server proxies `/api` to `http://localhost:3180` (see `proxy.conf.json`). The
control plane defaults to port 3180, so start it with `VECTISPIRE_PORT=3180` — or change the
proxy. They only have to agree.

## The stack, and why

**Angular 22.** Required by Optimus UI 2, whose peer dependencies are on `^22.1.4`. The
two move together: Optimus 1 declared Angular `^21`, and installing one major without the
other leaves a second copy of `@angular/core` in the lockfile, which does not build.

**TypeScript 6.0, not 7.** Angular 22 accepts `>=6.0 <6.1` and nothing else, so the range
is `~6.0.x` and a TypeScript minor is as much a framework decision as a major. The root
`package.json` carries an `overrides` entry for `openapi-typescript`, whose peer still says
`^5.x`: without it npm hoists a TypeScript 5 to the root, and ESLint type-checks with a
different compiler than the build.
It also carries `zod: ^4.6.6` (2026-10-25): `@angular/forms` reads Zod at run time, and
GHSA-mrhx-c7xc-m3w5 (memory exhausted by oversized constrained collections) is fixed in 4.6.6,
while `@angular/cli` pins exactly 4.6.5 — which kept the one shared copy on the vulnerable
version and made `npm audit --omit=dev` refuse the release. Remove the entry once
`@angular/cli` itself asks for 4.6.6 or later.

**Every component declares `ChangeDetectionStrategy.Eager`.** Angular 22 made OnPush the
default; `ng update` pinned the existing components to the old behaviour rather than change
it underneath them, and `eslint.config.js` says why the rule that would flag the pin is off.
A new component should not copy the pin.

**Optimus UI** (`@openng/optimus-ui`) rather than PrimeNG. PrimeTek archived the PrimeNG
repository and moved v22 to a commercial license; Optimus is the community fork of v21,
the last MIT release, and its 2.x line is that fork on Angular 22. The import subpaths are
identical (`@openng/optimus-ui/table` where you would have written `primeng/table`), which
makes the PrimeNG v21 documentation directly usable.

Two renames to know about, inherited from that fork:

| PrimeNG | Optimus |
|---|---|
| `PrimeNG` (configuration service) | `Optimus` |
| `providePrimeNG()` | `provideOptimus()` |

**Sparked** ([`openng-org/sparked`](https://github.com/openng-org/sparked), MIT) for the
shell: top bar, sidebar, dark theme, appearance configurator. Sparked is OpenNG's port of
PrimeTek's Sakai template onto Optimus UI; the shell came from Sakai first, and moving to
Sparked changed no behaviour — the layout stylesheets already matched Sparked's but for formatting,
and the components took only its upstream clean-ups (self-closing tags, `NgClass` or class
bindings instead of `CommonModule`). `LICENSE.md` beside this file is the template's own —
copyright PrimeTek, which Sparked keeps — and must stay there: MIT asks for the notice to
travel with the code that derives from it, and it was once deleted without anyone noticing.
The build copies it to `licenses/sparked/`, the jar serves it with `3rdpartylicenses.txt` under
`static/licenses/`, and `npm test` (`check-assets.mjs`) and the jar's build fail without it.
The Tailwind utilities Optimus colours (`text-primary`, `bg-surface-*`, `border-surface`,
`text-muted-color`, `bg-emphasis`, …) come from `@openng/optimus-ui-tailwindcss`, OpenNG's MIT
fork of `tailwindcss-primeui` 0.6.1: same utilities, same CSS output byte for byte.

Two things to know if you pull the template from source:

- Sakai kept `src/assets` in a **git submodule** (`cetincakiroglu/sakai-assets`), which a
  shallow clone does not fetch; Sparked has them in the tree, and so does this repository.
- The demo pages (`uikit`, `crud`, `landing`, `documentation`, …) have been removed. Only
  the shell, authentication and the error pages are kept.

**The icons are `@openng/icons`, not `primeicons`.** 8.0.0 followed PrimeNG under a
proprietary license — which is precisely what moving to Optimus was meant to avoid: the
PrimeUI license, free only below a revenue and headcount threshold, with a license key and
a ban on redistribution. It was read for 8.0.1 during the Angular 22 move and again for
8.0.2, which Dependabot proposed because an exact pin does not stop it from proposing.
`primeicons` stayed pinned to `7.0.0`, the last MIT release, until OpenNG published its MIT
fork of that release: same `pi-*` classes on the same code points — all 314 were compared —
so the swap changed no template. Read the license of any version before raising it.

**happy-dom, not jsdom, under the unit tests.** `@angular/build`'s Vitest runner takes
happy-dom whenever it resolves and jsdom otherwise; there is no setting, so the choice is
whichever package is installed. jsdom was held at 26 because jsdom 30 renamed a private
`Blob` field Vitest 4 reads, which broke every download spec. happy-dom ran the suite
unchanged, in less time. Keep it at 20.8.9 or later: earlier versions carry published
advisories, one of them a VM escape.

**`@vitest/coverage-v8`, at Vitest's own version.** `ng test` measures coverage on every run
and fails below the floors in `angular.json` — statements 76 %, branches 69 %, functions 65 %,
lines 78 %, set about three points under what the suite measured when they were introduced
(79.5, 72.0, 68.2, 81.2). Close enough that a screen landing without its specs turns the
build red, far enough that a rounding does not. On the `test` target rather than in a CI flag,
because a threshold only one pipeline passes is a preference, not a gate. The provider refuses
a Vitest of another version, so the two move together; raise a floor when the figure has
risen, never lower one to make a change pass. The HTML report lands in
`coverage/vectispire/index.html`. Dependencies MIT or BSD-3-Clause; development only.

**`mysql2`, exact-pinned, for the browser suite alone.** The Playwright suite runs the control
plane on MySQL (decision 0034), and two helpers in `e2e/support/fixture.ts` write to that
database directly — resetting the login throttle and seeding one finding — with the control
plane's own `VECTISPIRE_DB_*` variables, so both reach the same base. It replaced `node:sqlite`
when SQLite left the project. A development dependency: nothing in the bundle imports it. MIT,
its dependencies MIT except `long` (Apache-2.0); read them again before raising it.

## Asset checking

`npm test` starts with `scripts/check-assets.mjs`, which rejects any reference to a
third-party domain in `index.html`, `styles.scss` **and every component template**, and
verifies that the declared fonts actually exist and are real `woff2` files.

This is not zeal. Vectispire's content security policy refuses third-party stylesheets, and
the template (Sakai, and Sparked after it) loads Lato from a CDN. Such a reference breaks
nothing visible: the request is blocked, the page falls back to the system font, and nothing
reports it — which is how a typography can fail to reach production without anyone
noticing, until somebody measures it in the browser. Inter is therefore served from `public/fonts/`, OFL license included.

**The templates were added to that list after the rule missed something.** It read the
application shell only, and `auth/access.html` and `auth/error.html` each pulled an
illustration from `primefaces.org/cdn` — two screens nobody opens on an ordinary day, which
would have shown a missing image forever. Only asset positions are examined: `src`,
`srcset`, `url()`, and `href` on a `<link>`. An `xmlns` is not a request, a URL in a
`placeholder` is an example shown to the user, and an `<a href>` to an advisory is a
navigation the CSP does not govern — refusing all of those would make this the rule someone
switches off.

## Icon button checking

`npm test` also runs `scripts/check-icon-buttons.mjs`, which refuses a button showing an icon —
an `icon` attribute, or a `pi pi-…` element inside — with no accessible name: no `label`,
`ariaLabel`, `aria-label` or `aria-labelledby` in any binding form, and no text of its own. The
template lint cannot be trusted with it: `elements-content` reads native elements only, so an
Optimus `<p-button>` is invisible to it; on a native `<button>` the `<i>` of the icon counts as
content; and the inline templates of the layout are not linted at all. A `pTooltip` is not a
name — shown on hover, read by nothing.

**Every `pi-*` class must exist in the installed `openng-icons.css`.** Same failure, different
asset: an unknown icon class renders an empty box and reports nothing. `pi-balance-scale`,
`pi-file-code`, `pi-gitlab` and `pi-terminal` exist in no primeicons release and had been
blank on seven screens; they became `pi-building-columns`, `pi-file`, `pi-share-alt` and
`pi-code`. The known set is read from the stylesheet, so an upgrade that drops an icon fails
here too.

## Spec type checking

The specs are linted with the same type-aware rules as the code, `no-unsafe-*` included, and
`as never` and `as unknown as` are refused there by `no-restricted-syntax`. Those three rules used to
be off for `*.spec.ts`: `request.body` and `fixture.nativeElement` are `any`, so an assertion on
`body.expires_in_days` compiled whatever `TriageRequest` became, and twelve specs opened sessions
for a user with an `id` the server does not send. A request body is read as the type the client
method takes, the page as an `HTMLElement`; a word the client's union does not hold yet goes through
`newerServerWord` in `core/testing/contract.ts`.

`npm test` runs `scripts/check-spec-types.mjs`, which asks ESLint for the configuration it computes
for every spec file and fails if any of those rules is not an error there — the hole was an override
in `eslint.config.js`, not a missing rule — and holds the disable comments for them to a list,
each with its reason. It refuses a run that found no spec file.

## Test floor

`npm test` ends with `scripts/check-test-floor.mjs`, which runs `ng test` itself — one-shot,
with Vitest's JSON report written beside the console output — and then refuses any spec file
under `src/` that is absent from the run, ran no test, ran fewer tests than it declares, or
reported more skipped tests than it writes as skipped (a `describe.skip`, a stray `.only`).
What a file declares is counted from its syntax tree: one per `it(…)`/`test(…)`, one per
`it.each(…)(…)`; `it.skip`, `it.todo` and `xit` are declared as not running. A test generated in
a loop counts once, so the floor never exceeds a healthy run.

It exists because a run once reported 113 files green and 1287 tests where 1339 were expected —
`measurements.spec.ts`, 52 tests, gone — and Vitest saw nothing wrong; the cause never
reproduced. The floor is counted from the source rather than kept in a committed baseline, so
adding a test moves nothing else. Given any argument (`npm test -- --include=…`), the run may be
partial and the floor is not checked; the script says so.

## What the lint covers

`npm run lint` reads `src/`, `e2e/` and `playwright.config.ts` — the maintained recommended sets,
type-aware (`eslint.config.js` gives each exception its reason) — and then type-checks the
Playwright suite with `tsc -p tsconfig.e2e.json`. CI's `frontend` job runs it; `format:check`
covers the same files.

**The browser suite was outside both until 2026-10-15**, and nothing else compiles it: Playwright
strips the types and runs. Linted through the root tsconfig, it gave 105 findings that were nearly
all noise — TypeScript 6 includes no `@types` unless a config names them, so `process`, `Buffer`
and `node:*` were unresolved and `mysql2`'s connection, whose declarations build on Node's, had no
`execute`. `tsconfig.e2e.json` names `node` (`@types/node` is `mysql2`'s required peer, so it is
installed with it), and the e2e block of `eslint.config.js` lints against that file. Nine findings
remained, each fixed in the code — two logins now read `LoginResponse` from `api.generated.ts`. The
`no-unsafe-*` rules hold in `e2e/` as in `src/`, from the recommended set; the unit specs' cast bans
and `check-spec-types.mjs` stay with `src/`, since the suite's two `as unknown as` — the
`openapi.json` literal and Angular's debug `window.ng` — would each need an exception of their own.

`eslint-plugin-playwright` is not installed: `forbidOnly` already fails a stray `test.only` in CI,
and its other rules did not seem worth a dependency (and the `npm audit` that comes with one).

## Critical CSS inlining is off, and that is a security setting

`angular.json` sets `optimization.styles.inlineCritical: false` for the production build.
It reads like a performance choice and is not one.

With it on, the build emits `<link rel="stylesheet" media="print" onload="this.media='all'">`
so the stylesheet does not block the first paint. That `onload` is an **inline event
handler**, and Vectispire's CSP grants `script-src 'self'` with no `'unsafe-inline'`: the
browser blocks the handler, the stylesheet stays `media="print"`, and the interface renders
completely unstyled while every file loads with a 200. Nothing in the build output says so —
it was found by opening the page.

The alternative would have been `'unsafe-inline'` on `script-src`, which is the one
relaxation that hands an injected string the analyst's session. A first paint that is a few
milliseconds later is not a trade worth having that conversation over.
