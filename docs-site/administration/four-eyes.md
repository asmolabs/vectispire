# Four-eyes approval

A control that makes a triage decision take two people: one to propose it, another to approve it.

Switch it on in **Settings → VEX triage and approval**. With it off, a triage decision by anyone
who may triage settles immediately. With it on, the same decision enters an approval queue and
only an approver settles it.

## What it is for

A triage decision is not a note. `not_affected` with a justification travels, unchanged, into the
signed CycloneDX, OpenVEX and CSAF documents handed to customers. The control exists so that the
strongest claim this product can publish about a vulnerability is not one person's click.

It covers the three statuses that **settle** an issue — take it out of the gate's way: `not_affected`,
`will_not_fix` (*Will not fix — risk accepted*) and `fixed`. An accepted risk does not claim the
product is safe — the documents keep saying it is exposed, with no fix planned — but it stops failing
builds until its review date, which is a decision of the same weight as a clearance
([decision 0041](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0041-will-not-fix-is-not-not-affected.md)). Under the rule, a request by somebody who may not approve is queued as
`pending_approval`, still counts against the gate, and reads *under investigation* in every VEX
format until it is granted.

## Who approves, and who cannot

Approving is held by the roles that answer for the estate. The **platform governor** — the
bootstrap account — is deliberately **not** among them, and cannot triage at all.

That is the part worth understanding, because it is not an oversight. The governor is the one role
that can switch this control off. If it could also decide under the rule, the control would be
bypassable by one person in three moves: switch off, settle alone, switch back on, with a single
audit entry as the only trace. Removing the right to approve would not have closed that — the
service settles everyone's decision when the setting is off. What closes it is that **no role
holds both halves**: the one that can lift the rule cannot act under it.

## Switching it on requires that a second person exist

If no active account can approve, the server refuses to enable it. Without that guard, switching
it on where there is no approver puts every decision into a queue nobody can empty — a control
that blocks instead of controlling, and whose failure only shows at the first triage.

Create an administrator, a CISO or a security lead first.

It also refuses while **fewer than two active accounts can publish a checklist template** — the
platform governor, an administrator or a CISO. Under four-eyes a template version is published by
somebody other than its author, and writing it takes the same role: with a single such account,
every draft could be imported and none ever published. Create a second one first.
[Checklist templates](checklist-templates.md#5-publish) describes what the author of a draft is
told when the server refuses them as its publisher.

And it refuses while **fewer than two active accounts can approve** — an administrator, a CISO or a
security champion. Under four-eyes a project's checklist is signed off by an approver who wrote none
of it — who did not open it, answer or confirm a line, attach or withdraw a proof, nor submit it —
and approvers are often who fill checklists in: with a single one, whatever that approver answered
could be submitted and never signed off. Create a second one first.

The same count covers **report plugins**: under four-eyes a report plugin's manifest is approved by a
governance writer other than the platform governor who registered it, so the two accounts that let
templates be published let manifests be approved too
([Report plugins](report-plugins.md#registering-approving-switching-on)).

Switching it **off** stays possible either way: it is enabling that needs a second person.

## Signing a checklist off

A project's checklist is signed off by an approver. With four-eyes on, the server refuses the
sign-off by **any of the revision's authors** — the account that opened a fresh checklist, gave an
answer it holds, confirmed a carried line, attached or withdrew a proof, or submitted it, compared as
an account and as a name. Carrying answers over, by reopening or moving, is not writing.
The refusal is recorded in the audit log and sent to the SIEM (`VECTI-SEC-026`); a sign-off records
whether the rule applied. With four-eyes off, an approver may sign what they wrote.

## Decisions that arrive from a tracker

A ticket webhook can report a triage decision, and that decision never settles on its own —
whatever the tracker says. The route cannot hold a session, so it accepts nothing until a webhook
secret is configured; once it is, what arrives through it still goes to approval — the secret proves
the tracker sent the call, not that anybody looked at the vulnerability — and the audit entry
records the integration as the author with any claimed name kept beside it as reported data. A
tracker's refusal (*Won't Fix*, GitHub's *not planned*…) arrives as a request for `will_not_fix`, an
explicit false positive as one for `not_affected`; the approver chooses the status and the review
date. And an issue a person already settled is not moved by a ticket at all: the tracker's word is
recorded, and signalled as `VECTI-SEC-037` when it contradicts the decision
([Tracker tickets](../integrations/ticketing.md#inbound-webhook)).

## Related

- [Issues and triage](../guide/issues.md) — where a decision is proposed.
- [Users and teams](users-and-teams.md) — the roles and what each may do.
- [Checklist templates](checklist-templates.md) — a template version published by somebody other than its author.
- [Security checklists](../guide/security-checklists.md#5-sign-off) — a project's checklist signed off by somebody who wrote none of it.
- [SIEM](../integrations/siem.md#event-catalogue) — a checklist signed off (`VECTI-SEC-025`), a sign-off refused or a checklist returned (`VECTI-SEC-026`).
- [Audit log](audit-log.md) — where every decision and every setting change is recorded.
