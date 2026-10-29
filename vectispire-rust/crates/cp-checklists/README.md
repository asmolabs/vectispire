# vectispire-cp-checklists

The control plane's checklists module in Rust — `core.checklists` and the rules of `common.domain.checklists` (plan,
Phase 5; ported in wave 1, decided 2026-10-28). Not shipped: the Java control plane is the product. Staged, one pull
request per stage: **1a, this crate's vocabulary** (here); 1b the workbook reader and renderer; 2 the services and
persistence; 3 the 35 routes; 4 the replay of their recorded traffic.

## What it holds so far

| Rust | Java | |
|---|---|---|
| `text::normalize` | `ChecklistText` | NFKC, whitespace/separators/controls as one space, format characters removed, stripped — what every key and digest is computed over |
| `answer` | `ChecklistAnswer`, `AnswerAuthor`, `AnswerWords`, `GivenAnswer` | what an answer means, who gave it (a kind, never a name), the template's words for it |
| `item` | `ItemKey`, `EvidenceRequirement`, `ChecklistItem`, `ChecklistColumn` | a line's key across versions and its content digest (`Digests.sha256Fields`) |
| `pairing` | `VersionPairing` | unchanged, changed, added, removed; pairs made by hand |
| `contacts` | `ContactProfiles` | the profiles a contact column names; `AUTO` is none |
| `reminder` | `ChecklistReminder` | the weekly mails, plain text |
| `rule` | `ChecklistRule`, `Ratios`, `SeverityThreshold`, `ToolScope`, `AllowedComponent`, `CoverageScope`, `SuitePattern` | reading a rule as a request or a stored form states it, refused in Java's words and order; the canonical form and its SHA-256 |
| `evaluation` | `RuleEvaluation` | a rule over the facts and an instant: a `Measurement` |
| `measurement` | `Measurement`, `MeasurementOutcome`, `NoDataReason`, `Reconciliation` | the evidence as stored and its digest, read back |
| `source_languages` | `SourceLanguages` | which languages a static analysis must read |

What other modules build — the facts the owners of the evidence hand over (`MeasurementFacts`, `Look`) and a forge's
review reading (`ChangeReviewEvidence`, which `forges` writes) — is `vectispire_domain::checklists`, as the Java types
are `vectispire-common`'s; `MavenVersion` and its range are `vectispire_domain::maven_version`, the plugin id's rule
`vectispire_domain::plugin_manifest`, and the language vocabulary `vectispire_domain::language` (moved down from
`vectispire-protocol`, which re-exports it). The NFKC and Unicode-category reading stays in this crate: the agent links
`vectispire-domain`, and has no use for them.

Everything here is held to `reference/checklists/` (`ChecklistsReferenceSetTest` writes `java-answers.json` for
`inputs.json`; `tests/reference_set.rs` reads it): every refusal's sentence, every canonical form and digest, the
evidence of 128 evaluations, Maven's order on 6,670 pairs. The inputs are generated (`reference/checklists/inputs.py`); regenerate the Java side on
purpose, never to make a test pass. `security/mutants/p5-1a-checklists-domain.py` breaks each guard.

**Three Java defects fixed on the Java side first, then followed here** (asmolabs/vectispire#81): a branch-coverage
figure read "branchs" in the evidence a sign-off freezes; the reminder's cut could split a surrogate pair; a suite
pattern's leading `*` was spent on a name's own `*` (`*a` did not match `*xa`).

## Shaped for Rust

- **A rule is read from a tree of its own** (`node::Node`), not `serde_json::Value`: Jackson's node kinds are
  kept apart — an integral number from a decimal, which `isIntegralNumber` refuses for `maxAgeDays: 7.0` — and a
  decimal carries its digits, since a ratio is exact (`decimal`, `BigDecimal`'s reading and writing as far as a
  ratio needs). The route (stage 3) builds the tree from its form with the request's own digits.
- **Java's exceptions are two error types**: `Refused` for `InvalidInputException` (the caller's input, a 400) and
  `Defect` for `IllegalArgumentException` and `IllegalStateException` (a stored form that does not read, an argument
  no caller should pass); `Failure` where a constructor can raise either.

## Differences from Java, known

Decided 2026-10-28 by the stage 1a port; neither reaches a value a person has stored today.

- **NFKC is Unicode 18's** (`unicode-normalization` 0.1.26), JDK 25's is Unicode 16's; the general categories are
  Unicode 16's on both sides. A character assigned after Unicode 16 that has a compatibility decomposition normalises
  here and is left alone by Java: an item whose words hold one would get another key and digest.
- **A rule's text read by `ChecklistRule::parse_text`** (the stored canonical forms, the tests) goes through
  `serde_json`, whose decimals are doubles: a ratio written with more than fifteen significant digits is read as its
  nearest double's shortest digits, where Java reads every digit (and refuses it, past four decimals). A canonical
  form has four at most; the route's reading keeps the request's digits.
