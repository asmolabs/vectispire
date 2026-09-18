# Four-eyes approval

A control that makes a triage decision take two people: one to propose it, another to approve it.

Switch it on in **Settings → VEX triage and approval**. With it off, a triage decision by anyone
who may triage settles immediately. With it on, the same decision enters an approval queue and
only an approver settles it.

## What it is for

A triage decision is not a note. `not_affected` with a justification travels, unchanged, into the
signed CycloneDX, OpenVEX and CSAF documents handed to customers. The control exists so that the
strongest claim this product can publish about a vulnerability is not one person's click.

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

Switching it **off** stays possible either way: it is enabling that needs a second person.

## Decisions that arrive from a tracker

A ticket webhook can report a triage decision, and that decision never settles on its own —
whatever the tracker says, and whether or not a webhook secret is configured. The route is the
system's one anonymous door; what arrives through it goes to approval, and the audit entry records
the integration as the author with any claimed name kept beside it as reported data.

## Related

- [Issues and triage](../guide/issues.md) — where a decision is proposed.
- [Users and teams](users-and-teams.md) — the roles and what each may do.
- [Audit log](audit-log.md) — where every decision and every setting change is recorded.
