# Vectispire — Angular UI

Vectispire's user interface: the screens over the HTTP API that
[`vectispire-java/`](../vectispire-java/) serves.

```bash
npm start                 # from the root, serves on http://localhost:4280
npm run build
npm run lint              # ESLint, type-aware: TypeScript, Angular and template accessibility rules
npm run format            # Prettier at 120 columns; CI runs `format:check` and fails on unformatted code
npm test                  # asset, i18n and dead-API checks, then the Vitest suite
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

**Every `pi-*` class must exist in the installed `openng-icons.css`.** Same failure, different
asset: an unknown icon class renders an empty box and reports nothing. `pi-balance-scale`,
`pi-file-code`, `pi-gitlab` and `pi-terminal` exist in no primeicons release and had been
blank on seven screens; they became `pi-building-columns`, `pi-file`, `pi-share-alt` and
`pi-code`. The known set is read from the stylesheet, so an upgrade that drops an icon fails
here too.

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
