# 0041 — "Will not fix" is not "not affected": an accepted risk stays exposed in VEX, and every format reads the same triage

**Date:** 2026-10-10 · **Status:** accepted · **Builds on:** [0007](0007-none-is-not-an-empty-list.md) · **Decider:** Laurent Boucher

*Proposed before the code and accepted the same day: the owner settled the two questions the proposal
ended with, and the answers are written into the decision and listed at the end.*

## Context

Vectispire signs three VEX formats — CycloneDX, OpenVEX and CSAF — from one triage per issue. Each
statement in them is a claim made to a customer about a product. Several paths made a claim nobody had made.

**A tracker's refusal became "not affected".** `TicketingWebhookService` read a ticket closed as *Won't
Fix*, *Declined*, *Rejected*, *Risk Accepted* or *Withdrawn* (and GitHub's `not_planned`) and queued the
issue as `not_affected` with the justification `inline_mitigations_already_exist`. Since the webhook stopped
settling on the spot, the decision waits for approval — but the approver sees a status and a justification
the tracker never stated. Once approved, the signed documents assert that a mitigation exists in the product.
The ticket said something else: the team will not fix it. The first claim says the product is not exposed;
the second says it is, and the team knows. GitHub's `not_planned` was moreover read as a **false positive**,
with `vulnerable_code_not_in_execute_path`, although it is GitHub's only way to close without completing and
says nothing about reachability.

**A person accepting a risk had no honest status either.** The exceptions register recorded an acceptance as
`not_affected` with a justification the person chose — from a vocabulary of five in which none is true of an
exposed product.

**The formats did not read the same triage.** OpenVEX's aggregate generator looked for `false_positive` and
`accepted_risk`, statuses `TriageStatus` never had: every approved `not_affected` left as `affected`, and an
issue under review or awaiting approval as `affected`, where CycloneDX said `in_triage` and CSAF
`under_investigation`. The per-target CSAF export had no case for `pending_approval`, so such a product
appeared in no status list at all. The same issue was described differently in each signed document.

**And two generators invented a justification.** When a `not_affected` row carried none, CycloneDX wrote
`vulnerable_code_not_in_execute_path` and CSAF `vulnerable_code_cannot_be_controlled_by_adversary`, after
guessing from the spelling of whatever was there. `Triage.decide` requires one now, but older and imported
rows exist. CycloneDX also received OpenVEX's justification labels, which its schema does not accept, and
answered `will_not_fix` on every `not_affected` — nothing to fix in a product that is not affected.

## Decision

### 1. A fifth status: `will_not_fix`, settled once granted, with a review date

`TriageStatus.WILL_NOT_FIX(true)`: *judged to apply, and the team decided not to fix it* — an accepted risk.
It settles like `not_affected` and `fixed`: once granted it stops failing a gate, as an acceptance always did.
So it goes through four-eyes like them (`queueIfNotApprover` asks `isSettled()`), and it is an exception in the
register — counted as granted, reviewed, extended or revoked like a clearance. Two rules in `Triage.decide`:

- **a review date is required** — an acceptance without a date is the one nobody looks at again; it lapses
  back to `under_review` through `expireStale` like any other;
- **no VEX justification is accepted** — every one of the five says why a product is *not* exposed.

The column (`varchar(30)`) holds it without a migration; `settledWireNames()` includes it, being derived from
the flag.

### 2. A tracker's refusal is queued as `will_not_fix`, never as `not_affected`

The webhook maps *Won't Fix*, *Declined*, *Rejected*, *Risk Accepted*, *Withdrawn* and GitHub's `not_planned`
to `WILL_NOT_FIX`, with no justification and a **proposed** review date of ninety days — the tracker states
none, and whoever grants the request sets theirs. The ticket's comment is kept, with the claimed author, as
reported data. It goes through `triageView(…, false)` and is queued for approval: a tracker is not an approver.
**Only an explicit false positive** — *False Positive*, *Cannot Reproduce*, *Not an Issue*, or the words
"false positive" in a GitHub or GitLab issue — is still queued as `not_affected`: there the ticket does claim
something about exposure.

**A webhook does not move an issue a person settled** (`not_affected`, `will_not_fix`, `fixed`). It records the
tracker's word in the audit log and changes nothing. Where the tracker disagrees with the settled status, the
entry is `TRIAGE_CONTRADICTED_BY_TRACKER`, signalled to the SIEM as **`VECTI-SEC-037`** (outcome `detected`):
one of the two is wrong, and only a person can say which. A tracker that agrees is audited, not signalled.

### 3. One status, one statement, in every format

| Triage | CycloneDX `analysis` | OpenVEX | CSAF `product_status` |
|---|---|---|---|
| `under_review`, `pending_approval` | `in_triage` | `under_investigation` | `under_investigation` |
| `affected` | `exploitable` | `affected` | `known_affected` |
| `will_not_fix` | `exploitable`, response `will_not_fix` | `affected`, `action_statement` "Will not fix: …" | `known_affected`, remediation `no_fix_planned` |
| `not_affected` **with** a justification | `not_affected` + its CycloneDX spelling | `not_affected` + the recorded justification | `known_not_affected` + the recorded justification as flag |
| `not_affected` **without** one (older rows) | `in_triage` | `under_investigation` | `under_investigation` |
| `fixed`, or the issue resolved | `resolved` | `fixed` | `fixed` |

**A justification is never invented.** A `not_affected` row without one is nobody's claim, so it leaves as
*under investigation* — the "absent is not empty" rule ([0007](0007-none-is-not-an-empty-list.md)) applied to a
statement leaving the building. CycloneDX gets its own vocabulary — `code_not_present`, `code_not_reachable`,
`requires_environment`, `protected_by_mitigating_control` — paired with the OpenVEX labels as CycloneDX
publishes them.

The reading lives in one place, `VexDisposition.of` in `common.domain.vex`, which all five paths ask: the
three aggregate generators and the per-target OpenVEX and CSAF exports. It sits in `common` rather than in
`exports` because two of those paths are there. Three hand-written copies are how OpenVEX came to read
statuses that did not exist.

### 4. Checked by one table

`VexDispositionTest` checks every row of the table and that a resolved issue is fixed whatever its triage;
the export tests check how OpenVEX and CSAF spell an accepted risk, an unjustified clearance and a pending
request; `TrackerRefusalRoutesTest` checks the webhook's mapping, that a settled decision stays, and the
contradiction entry. A sixth status adds a row to the table, not a branch per generator.

## Consequences

- Issues a webhook put in `pending_approval` before this change keep their request `not_affected` +
  `inline_mitigations_already_exist`. **Before upgrading production, read the queue**
  (`triaged_by like '%_webhook'`) and turn down those that came from a refusal. No automatic migration: a
  person may have approved one knowingly.
- A team closing a ticket as *Won't Fix* sees a request for an accepted risk, not a clearance. Granting it takes
  the issue out of the gate's way until its review date, and the VEX documents keep saying the product is
  exposed.
- ~~**A pending request does not record which status was asked for.**~~ Lifted on 2026-10-12 — see
  *Amended* below: the request keeps its status, and an approval grants that status or is refused.
- The interface gains the status (label, filter, colour, the dialog requiring a review date and hiding the
  justification) in both languages; the triage guide and the VEX export reference change in `docs/{en,fr}/`
  and `docs-site/`.

## Rejected

- **Keep `not_affected`, with a "neutral" justification.** None of the five says "affected, accepted".
  Picking one is signing a falsehood.
- **Map the refusal to `affected`, without a new status.** The VEX loses the answer owed to the customer —
  *no fix planned* — and an acceptance could not be granted at all.
- **Leave `will_not_fix` unsettled**, as proposed. Honest about exposure, but it took away the only form of
  acceptance the register had without offering one: teams would have gone back to `not_affected`.
- **Ignore the refusal.** Synchronisation from the tracker would stop being useful for refusals, although the
  information exists.

## Amended on 2026-10-12: a request is granted as asked

The limitation above was a defect, not a deferral. Queued, a decision kept its justification, comment and
review date and dropped its status; the approver then chose one, and nothing compared the two. A
tracker's *Won't Fix* — queued as `will_not_fix` by §2 — could be granted as `not_affected`, and the
signed VEX then said "not exposed", which is the claim this decision exists to stop. And the dialog
emptied the proposed review date on opening.

- **Recorded.** V88 adds `t_issue.triage_requested_status` and `t_issue_triage_event.requested_status`
  (nullable, `varchar(30)`). `IssueTriageService.queueIfNotApprover` keeps the requested status; the
  issue carries it while `pending_approval` and any other decision clears it — an approval, a refusal,
  a lapse at the review date, a revoking review. The history row that queued the request records it.
  The proposed review date was already kept on the pending issue (`triage_expires_at`); no column for
  it.
- **Granted as asked, or turned down.** An approval (`origin = approval`) granting another settled
  status is refused, 409 with the type `urn:vectispire:problem:triage-approval-differs` and the member
  `requestedStatus`. An approver who disagrees answers `under_review` or `affected` — no approval —
  and may then decide under their own name. Letting the approver choose, with a comment and an audit
  entry, was rejected: four eyes on a status the second pair chose is one pair of eyes on it.
- **A VEX import does not answer someone else's request.** An upstream `not_affected` statement leaves
  a pending request for another status as it is, rather than failing the import on the refusal or
  replacing a person's request.
- **Shown.** `triageRequestedStatus` on every issue shape (`IssueView`, the backlog row, the detail) and
  `requested_status` on the exceptions register's entries; the backlog row and the register say what is
  asked, and the triage dialog opens on the requested status and the proposed review date.
- **Requests queued before V88** carry no status. They are granted as the approver chooses, as before;
  the advice in the first consequence above still applies to them.

Checked by `IssueTriageServiceTest`, `TrackerRefusalRoutesTest` (the webhook's requests, the 409 and the
grant, through the routes), `VexImportAuthorityTest`, and the interface's specs for the dialog and the
register.

## Decided on 2026-10-10

1. **Risk acceptance.** `will_not_fix` is settled once granted, with a mandatory review date — the honest form
   of an acceptance. It replaces the `not_affected` an acceptance used to be recorded as.
2. **A webhook on a settled issue** records without moving it, and a disagreement is signalled to the security
   lead (`VECTI-SEC-037`).
