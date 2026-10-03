# Checklist templates

A checklist template is **your organisation's own security checklist**, imported from the workbook
you already use: its domains, objectives, controls, contacts and KPIs, in its own words and its own
language. Projects answer it line by line — see [security checklists](../guide/security-checklists.md);
this page is where the template itself is imported, checked and published.

Open it from **Administration → Checklist templates**. Decision
[0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0032-security-checklists.md)
records why it works the way it does.

!!! info "Never published in one step"
    A workbook becomes a **draft**. Somebody confirms where the checklist is in it and what its
    answer words mean, its lines are paired with the previous version, and only then is it
    published. A published version never changes: a new word, layout or binding is a new version.

## Who may do what

| | Platform governor, administrator, CISO | Auditor | Everybody else |
|---|---|---|---|
| See the templates, their versions, the sheet, the layout, the items and the pairing | yes | yes | no — the entry is not in their sidebar |
| Import a workbook, confirm a layout, pair items, set what proof each line asks for, derive a version | yes | no | no |
| Publish a draft, retire a published version | yes, and with [four-eyes approval](four-eyes.md) on, **not the person who wrote it** | no | no |
| Set a draft aside | yes, the author included | no | no |

The auditor sees every screen described below without a single control that changes anything.

## 1. Import a workbook

Give the template a **slug** — 1 to 64 lowercase letters, digits and inner hyphens, such as
`release-checklist`. A new slug creates the template, named by **Template name**; an existing one
receives its next version and the name is not asked for. The **version label** is optional
(`2026 edition`).

The `.xlsx` is sent as it is. The screen refuses a file past **10 MB** before sending anything, with
the sentence the server would answer. The server refuses a macro-enabled workbook (`.xlsm`), the
binary format, and a file that fails one of its guards — more than 200 zip entries, more than 50 MB
uncompressed, an entry compressed more than 100 to one, a DTD in any part, an external
relationship target. A template has **at most one draft at a time**: while one exists, the import is
refused until it is published or set aside.

The source file is kept with its SHA-256, shown on the version: the signed documents of a later lot
are written into it, and an auditor can compare a delivered document with the template it claims to
follow.

## 2. Confirm the layout, on the sheet itself

Opening a version shows its sheet as a grid — row numbers down the side, column letters across the
top — with a selector for the workbook's other sheets. The reader has **proposed** a layout from the
workbook's structure: its validation ranges, merged cells, and which row is followed by a run of
filled rows. It never looks for expected words, which would be one organisation's vocabulary built
into the product. The grid draws the layout on screen over the cells:

- a column head names the field it holds — `C · Control`;
- the item rows of the named columns are highlighted in blue;
- the header cells are highlighted in amber;
- the column header row the reader found is in bold; `ƒ` marks a formula.

Correct anything wrong; the grid follows as you type.

| Part | What to give |
|---|---|
| Columns | The letters of each field. **Control, answer and comment are required**; identifier, domain, objective, contact and KPI when the template has them. An identifier column makes its values the items' keys; without one, a key is derived from the control's text. |
| Item rows | The first and last rows holding items, at most 5,000 rows. |
| Header cells | For the date, the product and the author, each only if the template has it: the label cell, left as it is, and the value cell, written into. Both or neither; never among the item rows, and two entries never share a value cell. |
| Answer words | The template's own words for **yes** and **no**, whatever its language. The answer list the reader found in the answer column's validation is shown beside them; the screen never maps it for you — which word means yes is yours to say. |
| Not applicable | Offered only if you tick it and name its word. When the template's list has no such word, type one: the document carries it, and the template's own list is left as it is. A not-applicable answer always needs its justification. |

**Confirm the layout** reads the items: blank domain and objective cells are filled down, as the
sheet means them, and a row whose control cell is empty is not an item. The items read appear below
the grid. Confirming again later reads them anew and **clears the pairs made by hand**, since they
named items as the earlier layout read them.

## 3. Pair the items with the previous version

Once the layout is confirmed, each item is compared with the previous published version:

| Change | What it means for a project's answer, when the project moves to the new version |
|---|---|
| Unchanged | Same key, same content: carried as it is. |
| Changed | Same key, different content — the wording, the KPI, the evidence requirement or the binding moved: carried, to be confirmed. |
| Added | No key in the previous version: starts unanswered. |
| Removed | Not in this version: its answer stays where it was given. |

A control that was only reworded shows up as one removed and one added item. **Pair them by hand**:
choose the added item and the removed one it is, and **Pair them**. The new item takes the old key
and becomes *changed*, *paired by hand*, so that a project's answer follows it, to be confirmed.
**Unpair** undoes a pair. A first version has nothing to pair with: every item is new.

Confirming a layout and pairing items are sent on the **revision on screen**, like publishing: when
another lead changed the draft after you opened it, your change is refused, naming the revision you had
on screen, rather than replacing theirs unseen. Reload the draft and make it again.

## 4. Say what proof each line asks for

A workbook states what each line asks, never what proof it needs, so every line of a new draft asks
for **none** — unless the line was there before: confirming a layout again keeps what each line
asked for, and a new workbook's line takes the requirement of the previous version's line with the
same key. On a draft with a confirmed layout, the **Proof asked** column of the items read offers,
for each line, the requirement:

| Requirement | What a *yes* needs before the checklist can be submitted |
|---|---|
| **None** (`none`) | Nothing. |
| **Link or file** (`link_or_file`) | A link or a file, in date. |
| **File** (`file`) | A file, in date — a link does not satisfy it. |

and, beside it, for a proof that expires, **how many months it holds**, 1 to 120 — each proof is then
valid until the day the work was done plus that many months. Leave the months empty for a proof that
does not expire; a line asking for none has no months to give, and the field is greyed out. The
screen refuses a validity outside 1 to 120, or not a whole number of months, before sending anything.

**Save the proof asked** sends the lines you changed, and only those — a line edited back to what it
asked is not sent, and the button counts the lines it will send. They are sent on the **revision on
screen**, like a layout, and whoever sets them becomes one of the draft's authors. On a published or
retired version, and for the auditor, the column only states what each line asks —
*Link or file · valid 12 months*.

The requirement is **part of what the line asks**: a line whose requirement moved is *changed*
against the previous version, and a project's answer carried onto it waits for somebody to confirm
it — the answer was given when no proof, or another one, was asked. A published version's
requirements never change; derive a new draft to change one.

## Measured lines: the rule a line is bound to

A line Vectispire can measure — dependencies analysed, no secret in the tree, static analysis clean
enough, coverage, an architecture suite that passed, internal libraries at maintained versions — is
**bound to a rule** on the draft, and each project's checklist then shows the rule's measurement
beside the answer. Vectispire never answers: it measures, and people answer.

On a draft whose layout is confirmed, the items table has a **Measured by** column. Choose **Bind a
rule** (or **Change the rule**) on a row: the form opens with the line's control and **its KPI, as the
template writes it, beside the parameters**, and under them *what the rule measures* in words. The KPI
is never read into a threshold; compare the two before keeping the rule — "no critical, at most two
high" against a rule that allows five is the disagreement this layout is there to show. Choose the
kind, state its parameters, and **Keep this rule**; **Preset: secrets at zero** fills the rule
decision 0032 names (the secret step, critical and high at zero open, evidence at most seven days
old). A findings rule's built-in steps are ticked; a plugin (`plugin:<id>`) or a tool a SARIF source
declares (`import:<source>/<tool>`) is typed, and the field suggests the plugins registered and the
tools of the SARIF sources declared. The form refuses, in words and before sending, what the server
would refuse. Choosing **No rule** and **Measure by no rule** unbinds the line.

Rules kept stay on screen, marked *Not saved*, until **Save the rules**: only the lines whose rule
changed are sent, on the draft's **revision** shown — one edited meanwhile is refused and the page
offers to reload. Only a platform governor, an administrator or a CISO binds rules, and whoever does
becomes one of the draft's authors; everyone else, the auditor included, and every published version,
shows each line's rule in words and nothing to change. A script does the same with
`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/rules?revision=…`, each line named by its
`itemKey` with its `rule`, or `null` to unbind it.

| Kind | What it reads | A line passes when, on every repository of the project |
|---|---|---|
| `dependency_analysis` | the newest scan whose dependency step produced | it is within the maximum age and kept its SBOM; if `requireSchedule`, the repository is scheduled at least as often as the maximum age; optional `thresholds` on the open vulnerabilities |
| `findings_threshold` | for each of its `scopes` — `builtin:secret`, `builtin:sast`, `builtin:iac`, `builtin:vulnerability`, `builtin:quality`, `builtin:eol`, `builtin:license`, `plugin:<id>`, `import:<source>/<tool>` — the newest scan or import in which that scope produced | every scope produced within the maximum age — for `builtin:sast`, `builtin:quality` and a plugin, on a tree whose languages it read ([what the analysis read](../guide/security-checklists.md#measured-lines)) — and the backlog meets the `thresholds` per severity: `maxOpen`, `minResolvedRatio` (resolved ÷ resolved and open), settled triage left out of both |
| `coverage_threshold` | the newest coverage import | it is within the maximum age and its `line` or `branch` ratio (`metric`) is at least `minimumRatio` — `per_repository`, or `project_weighted` (`aggregation`) — over the whole report, or over the packages its optional `scope` names ([below](#coverage-over-a-scope-of-packages)) |
| `test_suite_passed` | the newest test-report import | a suite matches `suitePattern` (`*` and `?`), those that match ran at least `minimumTests` (skipped ones not counted), none failed or errored |
| `component_versions` | the components of the newest analysed SBOM | every declared package (`purlPrefix`) is present at one of its listed `versions` — exact versions, and Maven ranges on a `pkg:maven/` package ([below](#components-presence-versions-and-ranges)) |
| `component_present` | the same components | every declared package (`purlPrefix`) is present, whatever its version — one the SBOM does not state included |

**Nothing is assumed.** Every kind requires `maxAgeDays` (1 to 366 — seven is a sensible start), a
dependency rule states `requireSchedule`, a findings rule states at least one threshold — *no
plaintext secret* is `builtin:secret` with every count at zero — and a parameter another kind takes
is refused rather than ignored. The KPI column stays the template's words: a threshold is a
parameter somebody wrote, never a number read out of a sentence. No package list ships with the
product; `component_versions` and `component_present` exist for the organisation that binds them with its
own.

A `purlPrefix` is a package URL without its version, and it matches a component whose package URL is
exactly it or continues it with `/`, `@`, `?` or `#` — `pkg:npm/left` does not match
`pkg:npm/left-pad`. To require every package of a namespace, stop before the separator:
`pkg:maven/com.example.tools`, not `pkg:maven/com.example.tools/`, which named no package and is
refused when bound. A line bound with the trailing `/` before that refusal keeps its text — its
digest reads it — and its measurement says it names no package; derive a draft to bind it again.

### Components: presence, versions and ranges

Both component kinds read the same inventory: the components of each repository's newest scan whose
dependency step produced within `maxAgeDays`. A line asking whether a library **is used** and a line
asking **which versions** are allowed answer from the same SBOM.

**"Library X is used"** is `component_present`. It passes when a component matches the prefix, whatever
its version — including a version the SBOM does not state, which is what Syft writes (`UNKNOWN`) for a
Maven dependency whose version a parent POM or a BOM manages. It fails when the inventory lists no
such component, and has no data when the repository has no analysis within the age, or when its
newest analysis no longer holds its SBOM and its inventory lists nothing (`inventory_absent`): an
absence nobody could have seen is not "not used".

```json
{ "kind": "component_present", "maxAgeDays": 7,
  "components": [{ "purlPrefix": "pkg:maven/org.example.platform/platform-application" }] }
```

**"The versions of family Y in use"** is a namespace prefix — `pkg:maven/org.example.platform` — on
either kind. The evidence lists, per repository, each package under the prefix with the versions its
occurrences state (twenty packages at most, the rest counted), so the reviewer reads what is deployed
and plans the updates beside the line.

**Allowed versions** are `component_versions`, its `versions` exact or, on a `pkg:maven/` package, Maven
ranges — written as Maven writes them and read in Maven's order:

| Entry | Allows |
|---|---|
| `1.17.7` | exactly `1.17.7`, as the SBOM writes it |
| `[1.17.7]` | `1.17.7` in Maven's order — `1.17.7.0` too |
| `[1.17,2.0)` | from `1.17` included to `2.0` excluded |
| `(,2.0)` | anything below `2.0` |
| `[1.0,1.2],[1.5,)` | a union: `1.0` to `1.2`, or `1.5` and above |

```json
{ "kind": "component_versions", "maxAgeDays": 7,
  "components": [{ "purlPrefix": "pkg:maven/org.example.platform", "versions": ["[1.17,2.0)", "1.16.4"] }] }
```

Maven's order is not a string's: `1.9` is below `1.17`; `1.17-SNAPSHOT`, `1.17-RC1` and `1.17-alpha` are
below `1.17`, so `[1.17,2.0)` refuses them and admits `2.0-SNAPSHOT`; `5.3.0.RELEASE`, `5.3.0.Final` and
`5.3.0` are one version; a service pack, `1.17-sp1`, follows its release. A range that does not read is
refused when bound, in words — a lower bound above the upper one, a lone version in parentheses,
ranges that overlap, a range admitting no version or every one (bind `component_present` for that). A
range on another type (`pkg:npm/…`) is refused: each ecosystem orders its versions its own way, and
only Maven's is implemented. A rule bound before ranges existed keeps its text and its digest, and
its exact versions their meaning.

**A version the SBOM does not state** is not judged by `component_versions`: a package none of whose
occurrences states one is `version_unrecorded`, and its evidence says the version is managed outside
the SBOM — a parent POM or a BOM — and that an SBOM produced by the build, which states it, resolves the
line. Where the line only asks whether the library is used, bind `component_present`.

### Coverage over a scope of packages

A `coverage_threshold` rule measures the whole report unless it names a **scope**: the packages it
measures, decided by the organisation in the template. Filtering in each build instead — JaCoCo's
`<includes>` in a `pom.xml`, a `--include` on the coverage tool — changes the figure where nobody
reviewing the checklist sees it; a scope is bound with the rule, shown beside its measurement and
printed in the signed document.

```json
{
  "kind": "coverage_threshold", "maxAgeDays": 7, "metric": "line", "minimumRatio": 0.8,
  "aggregation": "per_repository",
  "scope": { "include": ["**/service/**", "org/example/billing/**"], "exclude": ["**/generated/**"] }
}
```

In the form, **Packages measured** holds the two lists, patterns separated by commas; both blank is
the whole report.

**Patterns are over package paths**, as a coverage import keeps them: a JaCoCo package as JaCoCo
writes it (`org/example/service`), a Cobertura package with its dots read as slashes
(`org.example.service` is `org/example/service`; coverage.py's top-level `.` is the empty path), and
for lcov the directory holding each `SF:` file, as the tracefile spells it — an absolute path
included, which is why a pattern for lcov is best started with `**/`.

| Pattern | Matches | Does not match |
|---|---|---|
| `**/service/**` | `service`, `org/example/service`, `org/example/service/impl` | `org/example/services` |
| `org/example/**` | `org/example` and everything under it | `org/examples` |
| `org/example` | that package alone | `org/example/service` |
| `org/example/*-api` | `org/example/billing-api` | `org/example/billing/api` |
| `src/app/**` | `src/app`, `src/app/orders/web` (lcov) | `/builds/shop/src/app` — write `**/src/app/**` |

`**` is any number of whole segments, none included; `*` is any characters within one segment;
nothing else is a wildcard, and the comparison is case-sensitive. A package is **in the scope** when
an `include` pattern matches it — every package when `include` is empty — and no `exclude` pattern
does. Up to twenty patterns in each list.

**Refused when the rule is bound**, in words, rather than left to match nothing: a dotted package name
(`org.example.service` — write `org/example/service`), `**` inside a segment (`**/serv**`), `?`,
brackets, braces or `!` (which a reader would take for wildcards), a backslash, a leading, trailing or
doubled slash, a `.` or `..` segment, an empty pattern, one past 500 characters, a pattern listed twice,
and a scope with no pattern at all — leave `scope` out to measure the whole report.

**What it measures.** Lines (or branches) covered over those counted, summed over the matching
packages of each repository's newest coverage import — per repository, or over the project weighted
by size, as `aggregation` says. Each repository's evidence names how many packages matched —
*2 of 14 packages in the scope; 412 of 480 lines covered* — and the measurement's summary, which the
signed document's `Evidence` sheet prints, states the scope beside the figure, a pass included.

**No data, never a figure that is not the scope's:**

- `scope_matches_nothing` — no package of the report is in the scope: neither 0 % nor 100 %. Compare
  the patterns with the report's paths (lcov's are often absolute).
- `packages_unrecorded` — the newest import was accepted before imports kept their packages; only its
  totals are known. The pipeline's next upload measures the scope.
- `packages_not_kept` — the import kept its totals and not its packages: more than 10,000 of them, a
  path longer than 1,000 characters or carrying a control character, or per-package counts that did
  not add up to the report's totals ([what an import keeps](plugins.md#importing-coverage-and-test-reports)).

A rule without a scope is measured exactly as before, and keeps the canonical form — and so the
content digest — it had.

A binding is **part of what the line asks**, like its proof requirement: a line whose binding moved
is *changed* against the previous version, and a project's answer carried onto it waits for
confirmation. It follows its line's key — a layout confirmed again keeps it, a derived draft copies
it, a new workbook's line takes the previous version's binding under the same key. A published
version's bindings never change; derive a new draft to change one. The version's items carry the
binding as `boundRule`, structured as the rules route takes it; its canonical form — keys sorted — is
what the line's content digest reads and what the signed `checklist.json` states.

What a project's line then shows, and when a measurement refuses a submission or a sign-off, is in
[security checklists](../guide/security-checklists.md#measured-lines).

## 5. Publish

Publishing makes the version what projects open their checklists on. The button names the
**revision** on screen — the draft's edit counter — and that revision is what is sent: an edit made
by somebody else after you opened the page refuses the publication rather than publishing something
nobody here has read.

**Publishing fills the workbook in once, as a sign-off would** — every line answered and commented,
the header's product, author and date written — and keeps nothing of it: no document, no signature,
no audit entry. A workbook no sign-off could be written into is refused here, rather than at the
first sign-off, once a project has answered every line of a checklist that could never be signed. The
case met so far is [a formula in a cell Vectispire writes](#a-formula-in-a-cell-vectispire-writes).

When the server refuses — a publication, or any other change to a version — the screen says why, in
one sentence for each cause the server names (see [the table below](#refusals-for-scripts-and-integrations)),
and offers **Reload the version** where reading it again is the remedy:

- **You wrote this draft** — you imported or derived it, confirmed its layout, paired its items or set
  what proof its lines ask for — and four-eyes approval is on: **a second person must publish it**,
  another platform governor, administrator or CISO who wrote none of it. Every account that shaped the
  draft is its author, not only the importer. The screen warns you before you click, too.
- **The version changed since you read it**: the revision you had on screen is named. Reload it,
  review it again, then publish.
- **It has no confirmed layout**; **it is no longer a draft** because somebody published or set it
  aside meanwhile — derive a new draft from the published version to change it; **the template
  already has a draft**, when you import or derive another; **it is not published**, when you derive
  from a draft or a retired version; **it is already retired**; **it follows no published version**,
  so there is nothing to pair.

A refusal the server names no cause for is shown in the server's own words — and so is **no sign-off
could fill its workbook in**, whose sentence names each cell to correct.

### A formula in a cell Vectispire writes

A sign-off writes the **answer and comment cells of every item row** and the **value cells of the
header** — the date, the product, the author. Whatever those cells hold is replaced; a formula alone
there is replaced too, which is what happens to a `TODAY()` in the date cell: the document is dated by
the sign-off, not by whoever opens it next.

What cannot be replaced is a formula **other cells depend on**:

- **the master of a shared formula.** When a formula is filled down or copied across, Excel saves its
  text once, on the first cell, and the other cells only point back at it. Writing an answer or a
  comment over that first cell would leave the others pointing at nothing, and whoever opened the
  document would be asked to repair it. A helper in the comment column —
  `=IF(F7="Not done","Explain why","")` filled down — is the usual way in;
- **an array formula entered over several cells.**

The refusal names each such cell with the range depending on it — *Cell G7 (the master of a formula
shared across G7:G9) of the checklist sheet is a cell Vectispire writes…* — and, for a script, the
problem's `cells` member lists them: `cell`, `kind` (`shared` or `array`) and `range`.

**Correct the workbook by taking the formula out of the cells Vectispire writes** — their contents
are replaced at the sign-off anyway:

- **Excel**: select the cells named — for a whole array, *Home → Find & Select → Go To Special →
  Current array* — and *Home → Clear → Clear Contents*. To keep what they show as plain text instead,
  *Copy*, then *Paste Special → Values* on the same cells. If the helper must stay, cut it and paste
  it into a column the layout does not name.
- **LibreOffice Calc**: select the cells — for a whole array, *Edit → Select → Select Array* or
  `Ctrl+/` — and *Sheet → Delete Contents…* with *Formulas* ticked. To keep what they show, *Copy*,
  then *Edit → Paste Special → Paste Only Values*. Moving the helper works as in Excel.

Save, then **set the draft aside** — a version's workbook never changes once imported — and import
the corrected workbook. Confirm its layout again; the evidence requirements and rules are inherited
by key from the previous *published* version only, so set again what you had set on the draft you
put aside.

A version **published before this check** that has such a cell refuses every sign-off on it, in the
same words. Publish a corrected version as above, and have the projects
[move their checklists to it](../guide/security-checklists.md#7-move-to-a-newer-version): their
answers are carried. Meanwhile no checklist is opened on such a version, nor moved to it — the same
trial runs there and the screen names the cells (409 `checklist-version-unrenderable`) — while a
checklist already on it always moves away. Retire it once the corrected one is published, so that it is
no longer offered.

With four-eyes on, the platform refuses to be left with a single account able to publish — see
[four-eyes approval](four-eyes.md#switching-it-on-requires-that-a-second-person-exist).

## 6. Derive, retire, set aside

- **Derive a new draft** from a published version to change what a published version may never
  change in place: the same workbook, layout and items — each asking for the same proof — paired with the version it comes from, and a
  label of its own if you give one.
- **Retire** a published version: no new checklist opens on it, and every checklist already on it
  stays readable and exportable. With four-eyes on, it is retired by somebody who did not write it.
- **Set the draft aside** when it should never be published. That changes nothing any project
  attests to, so it asks nobody else, and the version shows as *retired*.

## Refusals, for scripts and integrations

Every refusal of a template route that depends on the state the version is in answers **409**, and
names its cause in the problem's `type`, `urn:vectispire:problem:` followed by the token below — so
that a script tells "read it again" from "somebody else has to do it" without reading the sentence,
which is written for a person and may change.

| `type` ends with | Meaning | What to do |
|---|---|---|
| `checklist-template-changed` | The draft changed since the `revision` you named | Read it again |
| `checklist-template-not-draft` | The version is published or retired | Derive a new draft from the published one |
| `checklist-template-no-layout` | The draft's layout is not confirmed | Confirm it first |
| `checklist-template-has-draft` | The template already has a draft | Publish it or set it aside first |
| `checklist-template-not-published` | Deriving from a draft or a retired version | Derive from a published one |
| `checklist-template-retired` | The version is already retired | — |
| `checklist-template-nothing-to-pair` | A first version: no previous one to pair with | — |
| `checklist-template-unrenderable` | At publication: no sign-off could fill the workbook in — a cell it writes carries a formula other cells depend on, each named in the problem's `cells` member | [Correct the workbook](#a-formula-in-a-cell-vectispire-writes), set the draft aside and import it again |
| `checklist-four-eyes` | Four-eyes approval is on and you wrote this draft | Somebody else publishes or retires it |

`checklist-four-eyes` is the token a project checklist's sign-off uses too: it means the same there.

## What is recorded

Every import, layout confirmation, pairing, evidence requirement set, rule binding, derivation,
publication and retirement is written to the
[audit log](audit-log.md). Publishing a version, and retiring a published one, is also signalled to
the SIEM as `VECTI-SEC-024`.

## Related

- [Security checklists](../guide/security-checklists.md) — a project's checklist, answered on a published version, and what
  moving it to a new version carries.
- [Four-eyes approval](four-eyes.md) — the setting that decides who may publish.
- [Users and teams](users-and-teams.md) — the roles and what each may do.
- [Audit log](audit-log.md) — where every change to a template is recorded.
