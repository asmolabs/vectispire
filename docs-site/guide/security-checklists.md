# Security checklists

A project's **security checklist** is your organisation's own checklist — a
[checklist template](../administration/checklist-templates.md) your security function imported and
published — answered for one project, line by line, by the people who build it, and then signed off
by an approver. Every answer keeps its author and its instant, every proof its date, and a signed-off
revision is never modified again.

Open it from **Solutions & projects**: each project you see whole carries a **Security checklist**
link. Decision
[0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0032-security-checklists.md)
records why it works the way it does.

!!! info "The whole project, or nothing"
    A checklist speaks for every repository of its project. It is shown to an account whose
    visibility is everything, to one granted the project as such, and to one that sees every one of
    the project's repositories — and there is at least one. Anybody else is told that the project
    *does not exist or is not visible to them*, the same words for both: a reader who sees part of a
    project would otherwise read, in one line, the state of repositories hidden from them. A project
    you see only in part has no checklist link in the tree.

## Who may do what

| | Administrator, CISO, security champion | User | Auditor | Platform governor |
|---|---|---|---|---|
| Read the checklist, its lines, its history and its earlier revisions | yes | yes | yes | yes |
| Open it, answer, attach and withdraw proofs, submit, return, reopen, move to another version | yes | yes | no | no |
| Sign it off | yes — with [four-eyes approval](../administration/four-eyes.md) on, **not an author of the revision** | no | no | no |

The auditor reads everything and changes nothing. The platform governor decides the rules — it may
write the templates — and takes no decision under them: it neither answers nor signs off. An account
that may not write sees the checklist without a single control that changes it.

## 1. Open the checklist

The page is headed with the project's name, even before it has a checklist. A project without a
checklist offers the **published** template versions. Choose one and **Open the checklist**:
revision 1 opens as a **draft**, you as its author, every line unanswered. A draft or retired version
is never offered.

A version published before Vectispire checked templates for it, whose workbook no sign-off could fill
in, is listed but **cannot be chosen**: it reads *cannot be signed off*, and a note beneath the list
names the cells at fault. It stays listed rather than hidden, so that a project whose checklist stands
on it sees where it went and what to report; ask whoever manages the templates for a
[corrected version](../administration/checklist-templates.md#a-formula-in-a-cell-vectispire-writes).
The **Move to another version** list marks it the same way.

A project has **one open revision at a time**. If somebody opened one after you loaded the page, your
opening is refused and the screen offers to reload — you see theirs rather than opening a second.

## 2. Answer the lines

The lines are grouped as the template groups them: by domain, then by objective, in the sheet's
order. Each shows its control, its contact and its KPI in the template's own words, the evidence a
"yes" needs, and what still keeps it from a submission:

| Shown on the line | What to do |
|---|---|
| Not answered yet | Answer it. |
| Awaiting confirmation | An answer carried onto a line that changed: answer it again, or **Confirm the answer**. |
| Comment required | A *no* or *not applicable* without its reason: answer again with a comment. |
| Evidence required | A *yes* on a line that asks for evidence, with none attached (or only a link where a file is asked). |
| Evidence out of date | Every proof attached is past its validity: attach a newer one. |

**Answer** a line with *yes*, *no* or — only on a version whose importer mapped a word to it — *not
applicable*; the template's own word is shown beside each. **A *no* or *not applicable* needs a
comment** (4,000 characters at most): the reader of the checklist needs the reason most on exactly
those lines. The screen refuses one without it before sending anything.

Answering never rewrites an answer: it adds a row to the line's **history**, under your name — the
signed-in account, never a name typed anywhere — and the newest row is the line's answer. **History**
on a line lists every answer given in this revision, oldest first, with who and when, and every proof,
withdrawn ones included.

A team fills one checklist together. Your answer is refused only when **that line** changed since you
loaded it — somebody else answered it or attached a proof — never because another line did; the
screen says so on the line and offers to reload.

## 3. Attach evidence

**Add evidence** on a line attaches a proof, with **the day the work was done** — a day, not in the
future:

- **a link** — an `https:` or `http:` address with a host, at most 2,000 characters;
- **a file** — at most **25 MB**. The screen refuses a larger file before sending a byte, with the
  sentence the server would answer; attach a larger document as a link.

A file is served back **only as a download**, as opaque bytes, whatever type it declared: an uploaded
HTML or SVG file opened in the page would be a script running on the control plane's origin. Its
name, size and SHA-256 are shown on the line.

When a line says how long a proof holds, each proof is **valid until** its day plus that many months,
and the line shows *Evidence out of date* once none holds. Evidence is asked of a *yes* only — a *no*
states that the control is not in place, and its comment says why. A line that asks for a file is not
satisfied by a link.

Which lines ask for a proof, of what kind and for how long, is the **template's**, set on its draft
before it is published — see [checklist templates](../administration/checklist-templates.md#4-say-what-proof-each-line-asks-for).
A line shows what it asks for; a line asking for none needs no proof, whatever its answer.

**Withdraw** a proof while the revision is a draft. It is never deleted: it stops counting, and it
stays in the list, struck through, with who withdrew it and when.

## 4. Submit, return

**Submit for sign-off** is greyed out, with the lines named, until every line is ready: answered,
every *no* and *not applicable* commented, every proof a *yes* needs attached and in date, and no
carried answer awaiting confirmation. A submitted revision is no longer answered.

Somebody who may write can **Return it to its authors** with a reason, which is kept on the revision
and shown in its header: it is a draft again, to be answered.

A submission, a return, a sign-off, a reopening and a move are refused when **anything** in the
revision changed since you loaded it — what is submitted or signed off is what you reviewed, line for
line. The screen explains the refusal and offers to reload.

## 5. Sign off

An administrator, a CISO or a security champion **signs off** a submitted revision: the release
attestation. With [four-eyes approval](../administration/four-eyes.md) on, the signer must be **none
of the revision's authors** — whoever opened a fresh checklist, gave an answer it holds (a carried
answer stays its author's), confirmed a carried line, attached or withdrew a proof, or submitted it.
Carrying answers over is not writing: reopening or moving does not make you an author. The header lists those authors, and the **Sign off** button is
greyed out for one of them with the reason: *a second person must sign it off*. The server decides —
the refusal is recorded in the audit log and sent to the SIEM (`VECTI-SEC-026`). With four-eyes off,
an approver may sign what they wrote.

A sign-off is also refused when a proof stopped holding since the submission — its validity ran out
in between. The lines refused are marked in red, each with what the server found missing — *Evidence
out of date*, for instance. Return the revision to its authors, who attach a newer proof and submit
again.

A signed-off revision states in its header who submitted it, who signed it off and when, and whether
four-eyes required the two to differ.

## 6. Reopen

A signed-off revision is never modified. **Reopen as a new revision** opens the next revision on the
**same version**, every answer and every proof carried as current — nothing to confirm, since no line
changed. The signed revision stays as it was signed, listed below.

Reopening or moving does **not** make you an author of the new revision: the answers carried stay
their authors', and you have said nothing about any line. An approver who reopens a checklist may
sign it off, provided they confirm, answer or attach nothing in it; whoever confirms a carried line
becomes an author, since confirming is where somebody vouches for it again.

## 7. Move to a newer version

When a newer version of the template is published, **Move to another version** opens a new revision on
it and **carries** the answers of the newest one:

| The line in the new version | Its answer |
|---|---|
| Unchanged | Carried as current. |
| Changed — its wording, KPI, evidence requirement or bound rule moved, or it was paired by hand with a reworded one | Carried **awaiting confirmation**: answer it again or confirm it before the revision can be submitted. |
| Added | Starts unanswered. |
| Removed | Its answer stays in the revision it was given in. |

A *not applicable* carried onto a version that does not offer it also awaits a new answer. Each carried
answer keeps the name and instant of whoever gave it, and names who carried it and when; the proofs
of an unchanged or changed line follow it, withdrawn ones excepted, re-dated against the new line's
validity. **Moving to
another template carries nothing**: the same words in another checklist are another question.

The revision it leaves becomes *superseded* if it was a draft or submitted; a signed-off one stays
signed off. Either way it stays readable.

The version moved to is tried first, as a sign-off would fill it in: one published before 0.10.0's
successor whose workbook no sign-off could fill in is refused, its cells named
([when the server refuses](#when-the-server-refuses)). The version moved from is never tried, so a
checklist stuck on such a version always moves away from it.

## Measured lines

A line the template binds to a rule — see
[checklist templates](../administration/checklist-templates.md#measured-lines-the-rule-a-line-is-bound-to)
— is **measured**: Vectispire reads what its scans, the plugins, the imports from your CI and the
backlog recorded for every repository of the project, and says what it found beside the answer.
The measurement is evidence beside the answer — and, unless your platform governor switched it off,
Vectispire also **answers the line itself** from it: see [automatic answers](#automatic-answers).

Each bound line shows, under its words, **Measured by** and the rule in words, then its measurement:
**Met**, **Not met** or **No data** — never a pass by default — with the reason in a sentence when
there is no data, the instant it is **as of** (its oldest evidence), the figures per scope and
severity, and **Show the evidence**: for each repository the scan (linked to its page) or the import
it read, its date, the digest of the document an import accepted, whether it met, and the server's
detail. A script reads the same at `GET /api/v1/projects/{id}/checklists/{revision}/measurements`.

The page says which measurements it shows. A draft's and a submitted revision's are **live**:
computed for your read, stored nowhere, read again after every change you make, and computed again
by the submission and by the sign-off. A signed-off revision's are the ones **frozen by its
sign-off**. Badges beside the outcome say what the answer and the measurement say together, and what
the measurement still keeps from a submission.

**No data says why.** One repository without data makes the line *no data*, and a threshold is never
judged on part of a project's backlog:

| Reason | Meaning |
|---|---|
| `no_repository` | The project has no repository: "every one of none passes" is not a pass. |
| `never_examined` | A repository has no scan or import in which the scope produced. |
| `step_absent` | Every scan within the age ran without the step or the plugin — did not look, not found nothing; also a coverage report that counted no branch, for a rule on branches. |
| `plugin_unsigned` | The plugin was refused, and did not produce since within the age: its manifest declares no signer, the executor requires one, and the governor [waived](../administration/plugins.md#running-an-unsigned-plugin) nothing. Nobody started the tool — sign its image, or record the waiver. |
| `plugin_signature_unverified` | The same, refused because the signer its manifest declares did not verify the image (another signer, no signature, or a registry cosign could not read). |
| `language_not_analysed` | The static analysis produced on a tree it could not read: a source language of the repository that none of the SAST rules the scan ran with reads, or a plugin that produced on a tree holding none of its languages. The evidence names the languages. Install rules for them — a rule set from the catalogue — and scan again. |
| `examination_unrecorded` | The scans within the age are from before Vectispire recorded which steps ran, or an import from before it recorded which tools it carried: rescan, or upload again. |
| `languages_unrecorded` | The scan the analysis produced in did not record its tree's languages, or the languages its rules read: every scan from before this version, a tree too large to count whole, an agent older than the census. Rescan with an up-to-date executor. |
| `version_unrecorded` | A declared package of a `component_versions` line is in the SBOM, and none of its occurrences states a version — Syft writes `UNKNOWN` for a Maven version inherited from a parent or a BOM it does not resolve. The package is present; its version was not recorded, so it is not judged. Where some occurrences state a version, those judge and the others are named in the evidence; a stated disallowed version, or a package absent from the SBOM, still fails. |
| `stale` | The newest look is older than the rule's maximum age. |
| `not_applicable_anywhere` | A plugin applies to none of the project's repositories: it looked at nothing. A repository where it is not applicable is left out of the figures when another is measured. |
| `suite_not_found`, `no_test_ran` | No suite of the newest test report matches, or those that match ran nothing. |

**Static analysis counts only what it read.** A line on `builtin:sast` or `builtin:quality` — both are
Semgrep and its rules — or on a plugin is judged by the languages the scan behind it recorded: those
its census found in the repository's tree, and those its analysis reads. Zero findings from rules that
read none of the code is not a clean result, and Vectispire would otherwise answer *yes* to it in a
document somebody signs.

- **Built-in SAST and quality:** every *source* language of the tree must be read by one of the rules
  the scan ran with — the bundled rules (one Python pattern) plus the rule set active **when the scan's
  task was built**, each rule counted for its catalogue directory (`java/…`, `javascript/…`). A set
  activated later does not reach back to older scans; scan again. Java read and TypeScript not is
  `language_not_analysed`, not a pass on the Java half. Rules an executor reads from its own
  `VECTISPIRE_SEMGREP_RULES_DIR` are on that executor's disk and are not counted.
- **Source languages** are those a program's behaviour is written in: every language of the vocabulary
  except `json`, `yaml` (data), `html` (markup), `dockerfile` and `terraform` (infrastructure — the IaC
  step's). `bash` counts: a shell script runs, and command injection is a SAST finding. A tree with no
  source language the census knows — code in a language outside the vocabulary, say — is not a tree
  whose code was analysed: `language_not_analysed`.
- **A plugin** must have read one of the tree's languages, by the manifest the scan ran it with (not
  the plugin's current one). The evidence names the source languages it does not read, without holding
  the line back for them: a plugin is chosen for what it declares.
- A line on a secret, IaC, dependency, licence or end-of-life scope, or on an imported tool, is not
  judged by language.

After an upgrade to this version, every line on these scopes reads `languages_unrecorded` until each
repository of the project is scanned again — no earlier scan recorded the languages of its rules —
and an automatic *yes* Vectispire gave there is withdrawn at the next measurement.

The backlog's figures leave **settled triage** out of both sides — *not affected*, *fixed* — and count
any other status, one this version does not know included.

**The answer beside the measurement:**

| Answer | Measurement | The line is | At submission |
|---|---|---|---|
| *yes* | pass | consistent | goes |
| *yes* | fail | **contradicted** | **refused** — answer *no* with the reason, or settle the findings by triage, which the figures then leave out |
| *yes* | no data | declared, not measured | goes **with a comment and a proof** in date, whatever the line itself asks |
| *no* | pass | understated | goes; the comment says why |
| *no* | fail | consistent | goes |
| *not applicable* | any | excluded | goes, commented |

An answer may **rest on the measurement** the person read: the answer names that measurement's
`evidenceDigest` (`measurementDigest`), the rule is applied again, and the answer is stored pointing
at the measurement stored with it. A measurement that moved since — a new scan, a new finding — is
refused rather than accepted unseen.

On the page that is **one click**: on a line measured *met*, **Answer yes, as measured** sends your
yes resting on the measurement shown; on a line *not met*, **Answer no, as measured** opens the form on
a no, which needs its comment. A line without data offers nothing to rest on: answer it yourself, and
a yes there then needs a comment and a proof. Choosing another answer than the measured one sends it
resting on none. If the measurement changed between your read and your click, the page reads it again
and says so on the line: read it, then answer.

**Every measured line at once.** `POST /api/v1/projects/{id}/checklists/{revision}/answers/as-measured`,
with the `edition` you read and, in `lines`, each line the page showed you as answerable with the
`measurementDigest` you read, gives that one click for every one of them where it needs nothing from
you: each named line, unanswered, still on the evidence you read and *met*, is answered *yes*, under
your name, resting on that measurement — a line of its history like any other answer, and one audit
entry each. Only what you were shown is answered: a named line whose evidence moved since your read —
a new scan, a new finding — is left alone as **measurement changed**, with what it is now, and a met
line you were not shown as **not shown**. It also leaves alone, and names with the reason: a line
**already answered** — whatever the answer,
even one awaiting confirmation or equal to the measurement: an answer somebody gave is never
replaced by a gesture that did not look at it; a line with **no data**; and a line *not met*, whose no
**needs a comment** — the one click opens the form for you to write it, and a comment the product
wrote under your name would be a claim you never made, so answer those one at a time. If anything was written on the
revision since the edition you read, nothing is answered (`checklist-changed`): read it again.

On the page, the act is the button **Answer every measured line as measured**, at the top of the lines,
under the note saying the measurements are live. It is offered to those who write, on the newest
draft, once the measurements are read, and only while at least one unanswered line shows its own
one-click button: it sends exactly those lines, each with the measurement its button would rest on.
A summary then stays above the lines until you close it or read another revision: how many lines were
answered yes as measured, then what was left alone, by reason — the lines *not met* waiting for your
no, each with a **Line N: answer no** button that opens its form on no, resting on the measurement,
the comment field ready; the lines whose measurement changed since you read it, to check again; the
lines without data, to answer yourself; a line met that you had not been shown; and a line you sent
that somebody answered meanwhile. A line leaves the summary once it is answered. A refusal is
explained like any other write on the page — `checklist-changed` with the offer to reload.

**Submit** is offered only once the measurements are read and none keeps the revision back — a yes
contradicted, or a yes without data missing its comment or its proof — which each line's own state
does not know; the page names the lines. A submitted revision whose measurement is no longer the
submission's greys out the **sign-off**, with the reason. Should the server refuse all the same
(`checklist-measurement-contradicted`, `checklist-measurement-changed`), the lines it names are
highlighted with the answer, what is measured now and, at a sign-off, what the submission found.

**Freshness is judged again at every step.** The submission measures every bound line again and
stores what it found, each with the answer it was reconciled with. The sign-off measures again, and
**is refused when a line's outcome or its reason is no longer what the submission stored** — a
signature must not attest to evidence that stopped being true in between (and a line that started
passing is a picture the submitter did not attest to either). The refusal is recorded and signalled
like any refused sign-off; return the revision, and submit it again. An accepted sign-off stores its
measurements: a signed-off revision reads its measurements as they were signed, whatever the
backlog does next.

## Automatic answers

With the platform setting [**Answer measured checklist lines automatically**](../administration/settings.md#security-checklists)
on — the default — **Vectispire answers the measured lines of a draft itself**, from their
measurement, so that a checklist arrives filled with everything the scans can state:

| The measurement | Vectispire's answer |
|---|---|
| Met | *yes* |
| Not met | *no*, with a comment written from the measurement — the rule and what failed it, starting with *Measured by Vectispire* |
| No data | nothing |

The comment is written **in English**, like the *Evidence* sheet: the platform states no document
language, and your organisation's own words are the template's (its yes and no), not the product's
sentences.

**When.** When a scan completes on a repository of the project, when a SARIF, coverage or test report
is accepted for one, and when the checklist is opened, moved to another version or reopened — the page
you are sent to already shows the answers. After a scan or a report, the answers arrive **within a
minute** rather than at once: the scan or the import queues them with its own results, and the
scheduler's next relay gives them, retrying if answering fails — so a server that stops at the wrong
moment still answers when it starts again. Never on a submitted or signed-off revision, and never
because somebody read the page.

**Who.** The author is **Vectispire**: no account, no role. Every such answer shows *automatic* beside
its author, rests on the measurement that produced it, is a row of the line's history like any other,
and is written to the audit log as `CHECKLIST_ANSWERED` **with no user** — nobody asked — and a
description naming Vectispire. What tells an automatic answer from a person's is its **kind**,
`answeredByKind: system`, never the name: an account may be called *Vectispire*, and its answers are a
person's.

**People first.**

- **A person's answer is never replaced** by Vectispire — any answer somebody gave, one carried from an
  earlier revision and awaiting confirmation included.
- **Answer a line yourself and it is yours**: your answer replaces Vectispire's, and the scans leave it
  alone from then on — even if the measurement then contradicts it, which the submission will name.
- **Vectispire replaces its own answer only when what it states changes** — its value, or its
  generated comment, which carries the figures: a *no* whose "5 open" becomes "3 open" is answered
  again. A new scan that measures the same thing writes nothing, however often the checklist is opened
  or scanned: the revision's edition does not move under the people filling it. The history keeps
  every answer.
- **When the measurement no longer has data** — the newest scan fell past the rule's maximum age, a
  step stopped producing — Vectispire **withdraws** its own answer: the line is unanswered again, and
  its history shows the answer and its withdrawal. A *yes* left standing on data that is no longer
  there would be a claim nobody makes any more.

**What still takes a person.** Submitting and signing off are unchanged — people, under
[four-eyes](../administration/four-eyes.md). The submitter attests to the whole revision, automatic
answers included. Vectispire is **none of the revision's authors**: four-eyes compares the people who
wrote it. The submission's rules apply to automatic answers as to any: a *no* carries its generated
comment, so it goes; an automatic *yes* on a line that asks for **a file or a link still needs that
proof** — attach it, or the line keeps the revision back as *evidence required*.

**On the page.** An automatic answer carries the badge **Automatic — measured by Vectispire** beside
it, is *answered by Vectispire*, and its generated comment shows as the line's comment. The header
counts them — **N automatic answer(s)** — so that you see at a glance what the scans filled, and what
is left for you. The line stays yours to answer: **Change the answer** opens the form with
Vectispire's answer and comment in it, and says **Answering replaces the automatic answer: the line
becomes yours.** In the line's **History**, Vectispire's rows are marked *automatic*, and a withdrawal
reads **Automatic answer withdrawn (no more data)**. **Answer every measured line as measured** is still
there, offered only for the lines still unanswered — with the setting on, that is mostly none.

**Switched off**, nothing new is answered automatically; the answers already written stay, each marked
as Vectispire's, until somebody answers over them. Answering as measured in one click remains.

## The document

`GET /api/v1/projects/{id}/checklists/{revision}/document` returns the revision as a document to hand
over: a zip, always served as a download.

| Entry | What it is |
|---|---|
| `checklist.xlsx` | **Your template's own workbook, filled in.** Every part of the file is the template's, byte for byte, except the cells written: each line's answer — in the template's own word — and comment, and the header's product, author and date. The validation lists, extensions, comments and styles are untouched. The date is a **value, the sign-off instant** — a formula such as `TODAY()` is replaced, since it would date every copy to the day it was last opened. One sheet is added, **Evidence**: one row per line with its answer, who gave it — *Vectispire (automatic, from its measurement)* for an automatic answer — and when, the measurement's outcome, the instant it is as of, the summary and SHA-256 of its evidence, what the answer and the measurement say together (*declared, not measured* for a yes without data), the proofs' links and file digests; then who submitted, who signed off, and whether four-eyes applied. Instants are UTC. |
| `checklist.json` | The same statement, machine-readable: project, revision, template slug, version and source SHA-256, every line with its current answer and history — each answer with its `answeredByKind`, `person` or `system`, and a withdrawal by Vectispire marked `withdrawn` (statement `form` 2) — its measurement (rule and evidence as the exact texts their digests cover) and its proofs — files named by SHA-256, never included — the submitter, the signer and the Vectispire version. |
| `checklist.xlsx.sig`, `checklist.json.sig` | Detached signatures by the platform's signing key — **a signed-off revision only**. |

**A signed-off revision's document is produced and signed with its sign-off** and stored: every
download returns those same bytes, whatever changed since. A draft, a submitted or a superseded
revision is rendered for the request, **unsigned**, its measured lines measured for it, its date cell
left empty and its Evidence sheet opening with *Draft — not signed off*.
A revision signed off **before signed documents existed** has no stored package: it is rendered the
same way, unsigned, and its Evidence sheet opens by saying it was signed off but no signed document was
produced then. The page still offers its download as a *signed package* — the status is all it sees —
so a zip without `.sig` entries is that case, not a fault.

On the checklist page, **Document** downloads the revision shown — *Download the signed package* for a
signed-off one, *Download an unsigned rendering* otherwise — and **Revisions** offers each earlier one's
the same way. A signed-off revision also shows the commands below, ready to copy, and a link to the
public key.

Anybody who may read the checklist may download it; so may an [integration key](../administration/api-keys.md)
with the `export` scope — though a key restricted to one repository never sees a whole project, and is
answered as if the project did not exist.

**Verify it against a key you obtained separately**, never one handed to you with the document:

```bash
curl -fsS -H "Authorization: Bearer $VECTISPIRE_TOKEN" -o checklist.zip \
  "$VECTISPIRE_URL/api/v1/projects/12/checklists/3/document"
curl -fsS -o vectispire-signing-key.pub "$VECTISPIRE_URL/api/v1/crypto/public-key.pub"
unzip checklist.zip
cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --signature checklist.xlsx.sig checklist.xlsx
cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --signature checklist.json.sig checklist.json
```

`--insecure-ignore-tlog=true` says only that the signature was never published to Sigstore's public
transparency log — Vectispire signs with its own key and publishes nothing — and it is required, or
cosign looks for an entry that does not exist. The key is what is checked.

## Earlier revisions

**Revisions** lists every revision of the project's checklist, newest first, with its status, its
version, who opened it and who signed it off. **Read** shows one as it stands, read-only: only the
newest revision is ever acted on.

## When the server refuses

Each refusal is named by its cause, and the screen says it in one sentence:

| The screen says | What happened |
|---|---|
| The checklist changed since you read it | Somebody else changed the revision after you loaded it. Reload, look, try again. |
| Somebody else wrote on this line | Another answer or proof arrived on the same line. Reload to see it. |
| This revision is no longer a draft / no longer waiting for a sign-off | It was submitted, signed off, returned or set aside meanwhile. |
| Only a signed-off revision is reopened / a newer revision exists | Act on the newest revision. |
| Not every line is ready | Lines still need attention: they are named, and each is marked *Refused for this line* with its problems — unanswered, comment required, evidence required or out of date, awaiting confirmation — as the server found them, which a proof lapsed since you loaded the page can make differ from what the line showed. |
| Four-eyes approval: a second person must sign it off | You wrote part of this revision. |
| A line is answered yes where its measurement fails (`checklist-measurement-contradicted`) | The submission is refused; the lines are named. See [measured lines](#measured-lines). |
| A measurement changed (`checklist-measurement-changed`) | At the sign-off: a line's measurement is not what the submission stored — return the revision. On an answer resting on a measurement: it is not the one you read — reload. |
| That version is no longer published / already on that version | Choose another version; after a sign-off, reopen instead. |
| No sign-off could fill in the workbook of the version you chose (`checklist-version-unrenderable`) | The version was published before Vectispire checked templates for it, and a cell a sign-off writes in its workbook holds a formula other cells depend on: the cells are named. Nothing was opened or moved. See below. |
| No carried answer awaiting confirmation / evidence already withdrawn | Somebody did it before you. |

A sign-off refused because **a cell of the template's workbook carries a formula other cells depend
on** — the sentence names the cells — cannot succeed on that version: the workbook is the template's,
and a published version never changes. Since the release after 0.10.0, a version is checked for it before
it is published, and a checklist is no longer **opened on, or moved to**, a version published earlier
that fails the same check: the screen names its cells, and nothing is opened, moved or recorded — a
checklist that could never be signed is not started. Ask whoever manages the templates for a
[corrected version](../administration/checklist-templates.md#a-formula-in-a-cell-vectispire-writes),
then open the checklist on it, or [move to it](#7-move-to-a-newer-version): your answers are carried.
**Moving away** from such a version is never refused — it is the way out for a checklist already on it.

## What is recorded

Opening, moving, reopening, every answer and confirmation — Vectispire's automatic answers and
withdrawals included, with no user and a description naming Vectispire — every proof attached or withdrawn, the
submission, the return, the sign-off and a refused sign-off are written to the
[audit log](../administration/audit-log.md), and so is each download of the document, with its SHA-256. A sign-off is signalled to the SIEM as `VECTI-SEC-025`; a
refused sign-off and a return as `VECTI-SEC-026`.

## Related

- [Checklist templates](../administration/checklist-templates.md) — where a template is imported,
  paired with its previous version and published.
- [Four-eyes approval](../administration/four-eyes.md) — the setting that decides who may sign off.
- [Solutions and projects](../administration/solutions-and-projects.md) — the projects a checklist
  belongs to, and the grants that decide who sees one whole.
