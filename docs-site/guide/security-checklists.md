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

## Measured lines

A line the template binds to a rule — see
[checklist templates](../administration/checklist-templates.md#measured-lines-the-rule-a-line-is-bound-to)
— is **measured**: Vectispire reads what its scans, the plugins, the imports from your CI and the
backlog recorded for every repository of the project, and says what it found beside the answer.
**Vectispire never answers**: the measurement is evidence, and the answer stays a person's.

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
| `examination_unrecorded` | The scans within the age are from before Vectispire recorded which steps ran, or an import from before it recorded which tools it carried: rescan, or upload again. |
| `stale` | The newest look is older than the rule's maximum age. |
| `not_applicable_anywhere` | A plugin applies to none of the project's repositories: it looked at nothing. A repository where it is not applicable is left out of the figures when another is measured. |
| `suite_not_found`, `no_test_ran` | No suite of the newest test report matches, or those that match ran nothing. |

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
| No carried answer awaiting confirmation / evidence already withdrawn | Somebody did it before you. |

## What is recorded

Opening, moving, reopening, every answer and confirmation, every proof attached or withdrawn, the
submission, the return, the sign-off and a refused sign-off are written to the
[audit log](../administration/audit-log.md). A sign-off is signalled to the SIEM as `VECTI-SEC-025`; a
refused sign-off and a return as `VECTI-SEC-026`.

## Related

- [Checklist templates](../administration/checklist-templates.md) — where a template is imported,
  paired with its previous version and published.
- [Four-eyes approval](../administration/four-eyes.md) — the setting that decides who may sign off.
- [Solutions and projects](../administration/solutions-and-projects.md) — the projects a checklist
  belongs to, and the grants that decide who sees one whole.
