# Users and teams

## Accounts

There is **no self-registration page**. An administrator creates every account.

The first one comes from the bootstrap variables at first start, and only when the user
table is empty — see [Installation](../getting-started/installation.md#the-first-account).
After that, both variables are ignored.

An account has an `is_active` flag. A deactivated account cannot sign in, and its history
stays intact — which is the point of deactivating rather than deleting one.

## Roles

Roles decide what a person may **do**; teams decide what they may **see**. The two are independent
by design: granting a role does not widen someone's scope, except for the three roles that
explicitly carry a global one.

| Role | What it can do |
|---|---|
| **User** | Sees and triages the findings of its own targets. Cannot single-handedly approve a decision that settles an issue while four-eyes approval is on. |
| **Security Champion** | As above, and may approve a triage — but only within the scope its teams grant. |
| **Auditor** | Sees the whole estate and **changes nothing**, anywhere. Reads the audit log, the compliance evidence, the gate policy, the rule sets and the SIEM configuration. Approves no triage. |
| **CISO / Security Lead** | Sees the whole estate, approves triages, and **writes** governance: gate policies, rule sets, SIEM destination, licence policy, settings. Does not administer accounts. |
| **Administrator** | All of the above, plus accounts, teams, API keys, SSH keys and agents. |
| **Superuser** | Identical to Administrator today. Created by the installation's bootstrap. |

**The auditor is worth a note.** It exists because "looking" and "being able to change" used to be
the same permission: the only way to open the audit log to someone was to also grant them the right
to rewrite the policy they had come to check. If you have to show your posture to an assessor, a
customer or an internal function, that is the role — not CISO.

Hand out administrative roles sparingly: the audit log is only as meaningful as the number of
people who can change what it records.

## Teams and visibility

Teams decide what a person can **see**. Targets are owned by teams, and every list, every
export and every trend series is narrowed by the reader's visibility — the dashboard's
backlog-over-time series included.

That narrowing is uniform on purpose. A view that quietly ignored it would let somebody
infer the shape of an estate they cannot open.

## Unlabelled targets

A target belonging to no team is visible only to those who can see everything. It is worth
checking for these after a bulk import: an unowned target is one nobody is responsible for,
and its scans still count in nobody's dashboard.

## Related

- [Single sign-on](sso.md) — delegating authentication without delegating authorisation.
- [API keys](api-keys.md) — for machines rather than people.
- [Audit log](audit-log.md) — what gets recorded about all of this.
