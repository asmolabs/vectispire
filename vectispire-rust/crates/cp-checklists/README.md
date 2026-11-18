# vectispire-cp-checklists

The control plane's checklists module in Rust — `core.checklists` and the rules of `common.domain.checklists` (plan,
Phase 5; ported in wave 1, decided 2026-10-28). Not shipped: the Java control plane is the product. Staged: **1a, the vocabulary**, **1b, the workbook**, **2, the services and persistence**, **3, the 35 routes** and
**4, the replay of their recorded traffic** — all here.

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

**The workbook (1b)**, held to `reference/checklists/workbooks.json` (`workbooks.py` writes it; `WorkbookReferenceSetTest`
answers it in `workbooks-java-answers.json`; `tests/workbook_reference_set.rs` reads it):

| Rust | Java | |
|---|---|---|
| `workbook_reader`, `zip_input` | `WorkbookReader`, `ZipInputStream` | the `.xlsx` read entry after entry from the local headers as JDK 25's stream reads it, every guard counted as the bytes come out of zlib — the ratio on the compressed bytes zlib consumed, 512 at a time |
| `safe_xml` (private) | `SafeXml` (`Doctype.REFUSED`) | a strict XML 1.0 reader with namespaces: a DOCTYPE refused, no entity but the five, the depth, attribute and element bounds; the JDK's events and its positions |
| `cell`, `workbook` | `CellRef`, `CellRange`, `CellValue`, `ListValidation`, `HeaderCell`, `Sheet`, `Workbook` | the grid, the values as stated, a validation list's words |
| `layout` | `ChecklistLayout`, `LayoutProposal`, `TemplateItems`, `TemplateVersion` | where the checklist lives, proposed from the structure and confirmed; the items filled down |
| `xml_cursor` (private) | `XmlCursor` | the tags with their offsets, what the renderer splices with |
| `renderer` | `ChecklistRenderer`, `EvidenceSheet`, `WrittenFormulaException` | the filled workbook, **the same bytes as Java's**, and its trial; every cell a formula depends on named |
| `document_zip` | `DocumentZip` | the archive `ZipOutputStream` writes, field for field, deflated by zlib at level 6 |
| `statement` | `ChecklistStatement` | the document's statement and `checklist.json` as the control plane's mapper writes it |

The reference set holds 186 workbooks — Office's shapes, the zip's guards and its corruptions, the XML's edges (70 of
them each with the JDK's line and column), the cells' types — 25 layouts, 11 versions, 28 renders and 4 trials compared
byte for byte, the statements, the serials and three archives. `fuzz/fuzz_targets/checklist_workbook.rs` fuzzes the
reader, the proposal and the trial every night; `tests/workbook_corruption.rs` runs a few thousand corruptions of the
same in the gate. `security/mutants/w1-checklists-1b.py` breaks each guard.

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
pattern's leading `*` was spent on a name's own `*` (`*a` did not match `*xa`). **And one in 1b**: a checklist row whose
`spans` attribute was `:` threw `ArrayIndexOutOfBoundsException` out of `ChecklistRenderer.within` — a 500 at the
sign-off of a template a person could open in Excel; it now reads as any other unreadable hint and is dropped.

**The services, persistence and routes (stages 2 to 4)**, held to the Java suite's recorded traffic by the golden replay
(`cp-agents/tests/golden.rs` composes the module as `cp-app/src/checklists.rs` does):

| Rust | Java | |
|---|---|---|
| `templates` | `ChecklistTemplateService`, `TemplateVersionStatus`, `VersionTrials` (`trials`) | import, layout, pairs, evidence, rules, derive, publish (four-eyes, independence, the trial rendering), retire, preview |
| `project_checklists` | `ProjectChecklistService`, `ChecklistStatus`, `LineProblem`, `MeasurementPurpose` | open, move, reopen, answer (resting on a measurement), as measured, Vectispire's own answers, confirm, proofs, submit, return, sign off, measurements |
| `measurer` | `ChecklistMeasurer`, `ChangeReviews` | the facts asked of their owners through ports: `ScanEvidence` (scanning, issues, inventory, targets — `internal::owners`), `ImportEvidence` and `ReviewEvidence` |
| `documents` | `ChecklistDocumentService` | the package signed inside the sign-off, served as stored; any other revision rendered unsigned |
| `contact_service` | `ChecklistContactService`, `ChecklistReminderService` | profiles linked to accounts, the weekly reminder |
| `carried` | `CarriedRepositories` | a frozen measurement read only by who sees every repository it carried |
| `forms` | `StoredForms` | the layout, pairs and authors a version's row keeps, and a bound rule in the API's shape |
| `persistence` | the ten repositories | checked statements on both engines (`.sqlx/`), the purge of a deleted project |
| `internal::reactions` | `ChecklistPurge`, `AnswersFromEvidence`, `ChecklistAnswerDelivery`, `ChecklistReminderTask` | `ProjectDeleted` (`cp-targets`' `ProjectPurge`), `RepositoryScanned` (queues `checklist_answer`), its outbox handler, the hourly slot |
| `web` | the three controllers | 35 routes, read in Spring's order |

**Stand-ins until their modules are ported**, each answering "nothing known" — never a pass (decision 0007):
`measurer::NoImports` for the plugins' imports and manifests (coverage, test reports, SARIF tools, a plugin's
languages: wave 2), `measurer::NoReviews` for the forges' readings (wave 3), `ports::NoMail` for the mail channel, so
the weekly reminder prepares and marks nothing until `notifications` is (wave 3). `ChangeReviewDemand` (what the forges
read) and `statementsForExport` (the project export's part) come with `forges` and `exports`.

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

Decided 2026-11-17 by the stage 2 to 4 port:

- **A ratio read back from a stored rule, or from a request, goes through a double**: `0.80` is read as `0.8`. Java's
  `BigDecimal` keeps the scale, so a rule bound with trailing zeros gets another canonical form and digest here.
  Neither side's suite binds one.
- **A link proof's address is checked by this crate's reading of `java.net.URI`** (`links`): an `http` or `https`
  scheme and a server-based host. A host `URI` reads as registry-based (an underscore in a label) is refused on both.

Decided 2026-11-16 by the stage 1b port, for workbooks Office does not write:

- **The XML reader is this crate's, not the JDK's.** It refuses what the JDK refuses on every case of the reference
  set and names the same line and column there; on a malformed part outside it the sentence is the same and the
  position may differ, since it is where this parser stopped. A DOCTYPE is refused as a DOCTYPE whatever follows it,
  where the JDK may first find the declaration malformed. Names are XML 1.0 fifth edition's.
- **Encodings**: UTF-8 (with or without its mark), UTF-16 by its mark or its first bytes, ISO-8859-1, US-ASCII and
  windows-1252 are read; any other declared encoding is refused once the declaration is read, where the JDK reads
  every charset its runtime knows.
- **A character reference to a surrogate** in an attribute the renderer rewrites is left as written; Java would write
  a lone surrogate. The reader has refused such a part already, so neither side reaches it.
- **A header with no author** is a defect here; Java's renderer throws a `NullPointerException` on it.

And one thing that is Java's and reproduced, not a difference: a directory entry's data is inflated outside the
counters when the next entry is read, as `ZipInputStream.closeEntry` discards it — CPU spent, nothing kept.

**The bytes are zlib's on both sides.** The renderer deflates through `flate2` on `libz-sys` (the zlib libgit2 already
links), the JDK through the zlib it is built with; every zlib 1.2.x and 1.3.x deflates alike at level 6, and the
reference set proves it on this build. A JDK linked against zlib-ng (some distributions ship it as `libz`) writes
other bytes — for Java too, a document rendered twice on two such hosts would differ.

