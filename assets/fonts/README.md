# Inter, bundled

## Why the file is here rather than a URL

The previous stylesheet was loaded from `fonts.googleapis.com`, and **Zanshin's CSP
refused it**: `style-src 'self'` (see the `helmet` block in `backend/src/main.ts`) allows
no third-party stylesheet. The font was therefore never applied in production — the UI ran
on the system fallback, with the intended geometry and somebody else's typography.

Widening the CSP would have been the easy fix and the wrong one. A security console that
calls a third party on every page load makes its own dependency inventory false, leaks
every analyst's address to that third party, and stops working on an isolated network —
the network where this kind of tool is precisely deployed. `font-src 'self' data:` was
already there; only the file was missing.

## Why Inter and not Lato

Two reasons, one aesthetic and one legal.

**The digits.** Inter carries real tabular figures (`tnum`) and slashed zeros (`zero`).
Zanshin is an application of columns of numbers — CVSS, EPSS, counters, dates. With a
proportional face, `9.8` and `10.0` are not the same width and the columns wobble from row
to row.

**The license.** SIL Open Font License 1.1 (`LICENSE.txt`): redistributable in a free
repository, which is Zanshin's situation. It requires keeping the license text and not
selling the font on its own — both satisfied by the presence of this directory.

## What the files contain

Two Unicode subsets of a *variable* font (one continuous weight axis from 400 to 800, not
four files):

| File | Range | Weight |
|---|---|---|
| `inter-latin.woff2` | latin | 48 KB |
| `inter-latin-ext.woff2` | latin extended | 85 KB |

The second covers the characters the first does not; the browser downloads only the one it
needs, thanks to the `unicode-range` declarations in `assets/theme.css`. The other upstream
subsets (Cyrillic, Greek, Vietnamese) are not bundled.

Source: `https://fonts.gstatic.com/s/inter/v20/`, the subsets Google Fonts serves for
`family=Inter:wght@400..800`. To update them, fetch the CSS with a browser user agent, read
the `latin` and `latin-ext` URLs from it, and replace the two files — the `unicode-range`
values in `theme.css` should be re-checked at the same time.
