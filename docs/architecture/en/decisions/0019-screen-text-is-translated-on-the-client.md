# 0019 — The server sends a token; the screen holds the sentence

**Date:** 2026-09-18 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

The interface is bilingual. 1132 keys exist in both bundles, no label is hard-coded, and three
ratchets in `check-i18n-keys.mjs` keep it that way.

Four files sent French sentences over the API, and the screens printed them as they stood:

- `EpssRiskMatrix` — `"P0 - Remédiation sous 24h (Catalogue CISA KEV…)"`, rendered by the EPSS
  screen **under a column header that goes through the bundle**. The heading changed language, the
  cell below it did not.
- `LicenseConflictMatrix` — a legal explanation and a remediation advice per licence category,
  plus nine matrix notes.
- `AttackPathService` — a note on every graph node, and a title, a narrative and a three-step plan
  per attack path, assembled by concatenating a method, a path and a package name into French
  prose.
- `AiVulnerabilityAdvice` — the advice this product writes itself when no model answers, shown on
  two screens, one field of it travelling into the `impactStatement` of exported VEX documents.

The rule that settles all four already existed, and only in a javadoc.
`RemediationGap.family` states it: *"a token and not a sentence: the sentence explaining how that
family is closed is screen text, and screen text is translated on the client."* It was invoked
five times to change a published contract, and a rule that governs an API while living in one
class's javadoc is a rule the next person reimplements differently.

## Decision

**A response field that a screen renders as prose carries a token. The sentence lives in the
client's translation bundles.**

The token is a **domain enum**, not a free string. springdoc enumerates an enum, so `openapi.json`
publishes the values, `openapi-typescript` generates an exact union, and a renamed constant fails
`ClientContractSpecTest` rather than reaching a screen as an unresolved key. `RemediationSeverityWireTest`
exists because the one place this was done with a hand-copied `@Schema` list needed a test to keep
the copy honest; an enum needs no such test.

**Values that vary travel beside the token, never inside the sentence.** A concatenation is
precisely what a translation cannot reorder: a French sentence built as `"…appeler l'endpoint " +
method + " " + path + "…"` cannot become an English one without taking it apart. `AttackPath`
therefore carries `Map<String, String> params`, and the bundle sentence interpolates `{{method}}`
and `{{path}}` wherever that language puts them.

**A screen renders literal keys.** `check-i18n-keys.mjs` reads literal keys only; a key built from
a token is invisible to the guard and ships unresolved the day it is missing. Templates use a
`@switch` over the token's values, and where the same switch would appear at several sites it is
written once in an `ng-template`.

## The exception, and why it is not one

`AiVulnerabilityAdvice` could not become a token. When a model is configured, **the model fills
those fields with its own prose, in whatever language it chose** — so they must stay free text.

What the server can say instead is *who wrote them*. A nullable `Deterministic` record travels
beside them, carrying the package, the two versions, what the reachability correlation managed to
say, and whether the CVE is actively exploited. Present, the screen rebuilds the sentence from the
bundles; absent, it prints the model's words untouched. Rewriting a model's sentence in this
product's words would be putting words in its mouth on a screen whose whole purpose is to show
what it said.

**The English sentences stay in place as the fallback**, for every consumer that does not
translate — the exported VEX document among them. That is the arrangement `Setting` already uses:
the server carries English, a bundle key overrides it when the reader has one.

## What this does not do, stated rather than implied

**It does not make API error messages bilingual.** The 32 thrown messages in the control plane are
English, deliberately and consistently; two were French and were aligned, not tokenised. An error
detail is read by a developer holding a response body more often than by a user reading a screen,
and tokenising every throw site would be a different decision with a different cost.

**It does not translate logs, prompts or stored data.** Operator logs are English. The prompt sent
to a model is an instruction to the model. A comment written into the audit trail is a record of
what happened, in the words it happened in.

**It does not close the guard's blind spot by itself.** `check-i18n-keys.mjs` cannot read a key
built at runtime, and until this work it could not read `[label]="…"` either — 32 hard-coded
labels sat in that gap, 25 of them English `aria-label`s that a French-speaking reader heard
through a screen reader. A third ratchet now reads inside bindings. It still cannot tell a
lowercase one-word label from a comparison value, and that limit is written in the file.

## Consequences

Five response shapes changed: `EpssPrioritizedIssue`, `LicenseConflict`, `CompatibilityCell`,
`AttackPathNode`, `AttackPath` and `AiVulnerabilityAdvice`. Each change regenerated `openapi.json`
and the client types with it.

Two domain tests that pinned French wording now pin the verdict instead — `contains("EXPOSITION
INDÉTERMINÉE")` became `isEqualTo(Exposure.NOT_MENTIONED)`. That is the better assertion
regardless of language: a verdict survives a rewording, a sentence does not.

A new screen that renders server prose must add an enum rather than a sentence. The cost is one
enum and two bundle entries; the cost of not doing it is an island of one language inside an
interface that follows the reader.
