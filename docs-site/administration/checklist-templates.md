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
same key. On a draft with a confirmed layout, set each line's requirement:

| Requirement | What a *yes* needs before the checklist can be submitted |
|---|---|
| `none` | Nothing. |
| `link_or_file` | A link or a file, in date. |
| `file` | A file, in date — a link does not satisfy it. |

and, for a proof that expires, **how many months it holds**, 1 to 120 — each proof is then valid
until the day the work was done plus that many months. A requirement is sent on the **revision on
screen**, like a layout, and whoever sets it becomes one of the draft's authors.

The requirement is **part of what the line asks**: a line whose requirement moved is *changed*
against the previous version, and a project's answer carried onto it waits for somebody to confirm
it — the answer was given when no proof, or another one, was asked. A published version's
requirements never change; derive a new draft to change one.

!!! note "Through the API until the screen offers it"
    The draft's screen does not set requirements yet. Until it does, a script sets them with
    `PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence?revision=…`, whose body lists
    the lines by their `itemKey` as the version shows it, each with its `evidenceKind` and, when a
    proof expires, its `evidenceValidityMonths`; lines not listed keep theirs.

## 5. Publish

Publishing makes the version what projects open their checklists on. The button names the
**revision** on screen — the draft's edit counter — and that revision is what is sent: an edit made
by somebody else after you opened the page refuses the publication rather than publishing something
nobody here has read.

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

A refusal the server names no cause for is shown in the server's own words.

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
| `checklist-four-eyes` | Four-eyes approval is on and you wrote this draft | Somebody else publishes or retires it |

`checklist-four-eyes` is the token a project checklist's sign-off uses too: it means the same there.

## What is recorded

Every import, layout confirmation, pairing, evidence requirement set, derivation, publication and
retirement is written to the
[audit log](audit-log.md). Publishing a version, and retiring a published one, is also signalled to
the SIEM as `VECTI-SEC-024`.

## Related

- [Security checklists](../guide/security-checklists.md) — a project's checklist, answered on a published version, and what
  moving it to a new version carries.
- [Four-eyes approval](four-eyes.md) — the setting that decides who may publish.
- [Users and teams](users-and-teams.md) — the roles and what each may do.
- [Audit log](audit-log.md) — where every change to a template is recorded.
