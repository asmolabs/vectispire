# 0020 — Screenshots stay PNG, and the trigger to change that is named

**Date:** 2026-09-21 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

`docs-site` carries 42 generated screenshots — 21 screens in two languages, 1280×860, 8-bit
truecolour PNG, **5.5 MB**. They are produced by `screens.spec.ts` rather than taken by hand, for
the reason that file's header gives: an image is coupled to the pixel, and `mkdocs --strict` can
see a dead link but never a picture of a column removed three months ago.

Being generated is what makes the size question worth asking at all. A hand-taken screenshot is
replaced when somebody notices it is stale; a generated one is **rewritten by every campaign**,
and git keeps each version forever. Two campaigns ran in the week of 2026-09-14, and the second
touched seventeen images for a reason that was not a redesign — the loading mask was being
captured mid-fade. The repository therefore grows by something close to the full 5.5 MB each time
a campaign sweeps, not by the size of what actually changed on screen.

Four options were measured rather than estimated, over all 42 files:

| option | total | fidelity |
|---|---|---|
| as committed | 5584 k | — |
| PNG re-encode (Pillow `optimize`, `compress_level=9`) | 5730 k | identical — **larger** |
| 256-colour palette PNG | ~2100 k | **degraded** |
| lossless WebP (`cwebp -z 9`) | **1999 k** | identical, verified |

Three results decided it:

**Playwright's PNG encoder is already at the optimum for this content.** Re-encoding loses 3 %.
There is no free lossless win sitting in the current format, which removes the option that would
have cost nothing to take.

**Quantization is dominated.** The captures hold only 1500–5800 distinct colours, so a 256-entry
palette does cut 62 % — but it spends the antialiasing of every glyph to reach the same figure
lossless WebP reaches without spending anything. An option that is worse on both axes than another
available option needs no further argument.

**Lossless WebP cuts 64 %, and the claim was checked rather than trusted.** `cwebp -lossless`
followed by `dwebp` returns a pixel-identical image; the round-trip was run on three captures and
`ImageChops.difference` found no bounding box on any of them.

## Decision

**The captures stay PNG. The conversion to lossless WebP is deferred, and the condition that
triggers it is written here rather than left to whoever next notices the directory is large.**

**Convert when a third axis is added** — a third language, or a second resolution. Both multiply
the file count rather than adding to it, and 64 % of a number that has just been multiplied is
worth the costs below. 64 % of 5.5 MB is not.

The costs, which is why the trigger is a multiplication and not a threshold:

- `page.screenshot()` emits png or jpeg only. WebP needs a conversion step after the capture, so
  **the committed artefact stops being exactly what the browser produced** — a property this
  suite is otherwise built around.
- `libwebp` becomes a dependency of the e2e job and of anybody regenerating locally.
- All 42 image references in the markdown change, in both languages.
- **A `cwebp` version change would rewrite all 42 files at once.** That is the same class of
  churn as the mask fix, and the same kind of diff nobody can read. If this is taken up, `cwebp`
  is pinned by digest the way `ScannerImages` pins Syft and Grype — for the reason given there:
  the tool that produces a committed artefact is part of the artefact.

## What this does not do, stated rather than implied

**It does not claim 5.5 MB is a problem today.** It is not. The argument here is about the slope,
not the value, and the decision it reaches is to do nothing — which is why the trigger has to be
written down. A deferral with no named condition is indistinguishable from an oversight, and
reopens as a fresh investigation every time somebody runs `du`.

**It does not cover the site's other images.** The C4 diagrams are generated SVG and are text;
none of the above applies to them.

**It does not licence hand-taken screenshots.** Nothing changes about how captures are produced,
only about the bytes they are stored in.

## Consequences

The next campaign commits PNG, as every previous one has. Nothing in `screens.spec.ts` changes.

A reader who finds `docs-site/assets/screens` large has this record instead of the investigation
that produced it: the numbers are here, the round-trip has been run, and the remaining question is
only whether the trigger has fired.

When it does fire, the work is a conversion step in `shoot()`, a pinned `cwebp`, one sweep of the
markdown references, and a single commit that changes 42 files for a reason the commit message can
state in one line.
