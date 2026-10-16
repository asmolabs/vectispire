# 0044 — A checklist's contacts are linked to accounts and reminded weekly

**Date:** 2026-10-16 · **Status:** accepted · **Builds on:** [0032](0032-security-checklists.md), [0023](0023-solutions-projects-and-repositories.md) · **Decider:** Laurent Boucher

## Context

A checklist template's contact column says who each line is to be asked of — as a role, not a person:
the organisation's workbooks hold *PO*, *BA*, *Arch*, *SII*, *PO / BA*, and *AUTO* on the lines a scan
answers. Decision [0032](0032-security-checklists.md) kept it as text (question 16) and left out
"assigning items to accounts from the contact column, reminders, due dates, notifications".

A first production deployment changes that: a checklist opened for a project is filled in over weeks by
several people, and nothing tells any of them that lines of theirs are waiting. The security lead chases
them by hand, project by project, from a column that names a role nobody is attached to.

What exists to build on: the column is stored per line (`t_checklist_item.contact`); the weekly posture
report already runs on the hourly tick and keeps its "sent this week" in the audit log; the mail relay
is configured by the deployment, but sends only to the global recipients of a setting; accounts carry an
optional e-mail address; and every checklist route refuses a project the caller does not see whole.

## Decision

1. **A profile is a value of the contact column, read from the cells.** Every value is a profile, but
   `AUTO`, which marks a line Vectispire measures. A cell is split on `/` — *PO / BA* is both profiles'
   line — and compared after the same normalisation as the template's words, upper-cased: *Arch* and
   *ARCH* are one profile, shown as first written. No closed list of PO, BA and architect: a list in code
   would remind nobody of the profile it forgot (*SII*), and the column is the organisation's.
2. **A project links each profile to one account** (`t_checklist_contact`, V91), kept by the profile's
   key rather than by a line, so the link outlives the template version it was made on. The profiles
   listed are those of the newest revision's version; a profile a newer version no longer names keeps its
   link, unused.
3. **The account linked can fill the checklist in**: active, of a role that answers checklists
   (`canCauseEffects` — not the auditor, not the platform governor), and seeing the whole project as its
   own account, under the visibility mode in force. Linking is refused otherwise, in one sentence for an
   account that does not exist and one that cannot fill it in. Linking and unlinking are a writer's —
   whoever may answer the checklist — and audited (`CHECKLIST_CONTACT_CHANGED`). The accounts offered are
   listed by id and a name, never an e-mail address, nor a name that is one.
4. **What remains to fill in is a line of the open draft with no current answer, or a carried answer
   awaiting confirmation.** A submitted revision is nobody's to fill in until it is returned. The other
   problems a line can have — a missing comment or proof, a contradicted measurement — are the
   submitter's, and stop the submission already.
5. **Once a week, each linked account receives one e-mail** at its own address, naming every such line
   of its profiles across its projects. **A profile with such lines and nobody to remind is the CISOs'**:
   linked to nobody, or to an account since deleted, deactivated, no longer able to fill the checklist in,
   or without an address. Every active CISO with an address receives the list of those profiles with the
   reason, each CISO only for the projects its own account sees whole.
6. **Off by default** (`checklist_reminders_enabled`, a notification setting, the security lead's like the
   posture report): an upgraded deployment does not start writing to its people. It needs the mail relay;
   with none, nothing is sent and nothing retried.
7. **The bookkeeping is the audit log, one entry per recipient** (`CHECKLIST_REMINDER_SENT`, its resource
   the week's Monday and the recipient), written after the send: a relay refusing one address is retried
   the next hour for that address alone. Neither entry is signalled to the SIEM: who is asked to fill a
   checklist in is work, not a security event.

## Consequences

- The mail channel gains a send to given addresses (`MailNotificationChannel.sendTextTo`); the
  `checklists` module depends on `notifications`.
- An account deleted through SCIM leaves its link naming nobody — the profile reads `account_gone` and its
  lines go to the CISOs until it is linked again. No foreign key: the checklist tables have none
  ([V52](0032-security-checklists.md)), and a project's links are purged with it by `ChecklistPurge`.
- Two control planes may both send in the same hour, as the posture report may; a duplicate is accepted
  over a lock.
- The message is plain text, in English, like every e-mail Vectispire sends: there is no template engine
  and no server-side translation.

## Rejected

- **A fixed list of PO, BA and architect.** The workbooks already carry *SII*; a fixed list would leave
  those lines to nobody, silently.
- **Linking a profile to a team.** 0032's question 16 suggested it. A team is an access grant, and a
  reminder to a team of twelve is read by none of them; one accountable person per profile is what the
  column asks.
- **Reminding every line with a problem.** A missing comment, proof or a contradicted measurement is the
  submitter's to resolve, and refuses the submission with the line named; the reminder is about lines
  nobody has answered.
- **Sending to the global e-mail recipients.** They are the security team's channel for scan alerts; the
  reminder is to the person who has to act.
