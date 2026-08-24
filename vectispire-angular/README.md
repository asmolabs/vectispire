# Vectispire — Angular UI

Vectispire's user interface: fifteen screens over the HTTP API that
[`vectispire-java/`](../vectispire-java/) serves.

```bash
npm start                 # from the root, serves on http://localhost:4280
npm run build
npm test                  # asset check + Vitest suite
```

The dev server proxies `/api` to `http://localhost:3180` (see `proxy.conf.json`). The
control plane defaults to port 3180, so start it with `VECTISPIRE_PORT=3180` — or change the
proxy. They only have to agree.

## The stack, and why

**Angular 21.** Required by Optimus UI, whose peer dependencies are on `^21.0.0`.

**Optimus UI** (`@openng/optimus-ui`) rather than PrimeNG. PrimeTek archived the PrimeNG
repository and moved v22 to a commercial license; Optimus is the community fork of v21,
the last MIT release. The import subpaths are identical (`@openng/optimus-ui/table`
where you would have written `primeng/table`), which makes the PrimeNG v21 documentation
directly usable.

Two renames to know about, inherited from that fork:

| PrimeNG | Optimus |
|---|---|
| `PrimeNG` (configuration service) | `Optimus` |
| `providePrimeNG()` | `provideOptimus()` |

**Sakai** (MIT, PrimeTek) for the shell: top bar, sidebar, dark theme, appearance
configurator. `LICENSE.md` is the template's own and must stay there.

Two things to know if you pull the template from source:

- `src/assets` is a **git submodule** (`cetincakiroglu/sakai-assets`). A shallow clone
  does not fetch it, and you then believe the repository is broken — `angular.json`
  references stylesheets that aren't there. Here the assets are copied in directly, not
  mounted as a submodule.
- The demo pages (`uikit`, `crud`, `landing`, `documentation`, …) have been removed. Only
  the shell, authentication and the error pages are kept.

**`primeicons` is pinned to `7.0.0`**, exactly. 8.0.0 followed PrimeNG under a
proprietary license — which is precisely what moving to Optimus was meant to avoid. The
constraint is a disguised `=`: do not loosen it without reading the license.

## Asset checking

`npm test` starts with `scripts/check-assets.mjs`, which rejects any reference to a
third-party domain in `index.html`, `styles.scss` **and every component template**, and
verifies that the declared fonts actually exist and are real `woff2` files.

This is not zeal. Zanshin's content security policy refuses third-party stylesheets, and
Sakai loaded Lato from a CDN. Such a reference breaks nothing visible: the request is
blocked, the page falls back to the system font, and nothing reports it — which is how a
typography can fail to reach production without anyone noticing, until somebody measures it
in the browser. Inter is therefore served from `public/fonts/`, OFL license included.

**The templates were added to that list after the rule missed something.** It read the
application shell only, and `auth/access.html` and `auth/error.html` each pulled an
illustration from `primefaces.org/cdn` — two screens nobody opens on an ordinary day, which
would have shown a missing image forever. Only asset positions are examined: `src`,
`srcset`, `url()`, and `href` on a `<link>`. An `xmlns` is not a request, a URL in a
`placeholder` is an example shown to the user, and an `<a href>` to an advisory is a
navigation the CSP does not govern — refusing all of those would make this the rule someone
switches off.

## Critical CSS inlining is off, and that is a security setting

`angular.json` sets `optimization.styles.inlineCritical: false` for the production build.
It reads like a performance choice and is not one.

With it on, the build emits `<link rel="stylesheet" media="print" onload="this.media='all'">`
so the stylesheet does not block the first paint. That `onload` is an **inline event
handler**, and Zanshin's CSP grants `script-src 'self'` with no `'unsafe-inline'`: the
browser blocks the handler, the stylesheet stays `media="print"`, and the interface renders
completely unstyled while every file loads with a 200. Nothing in the build output says so —
it was found by opening the page.

The alternative would have been `'unsafe-inline'` on `script-src`, which is the one
relaxation that hands an injected string the analyst's session. A first paint that is a few
milliseconds later is not a trade worth having that conversation over.
