# Users and teams

## Accounts

There is **no self-registration page**. An administrator creates every account.

The first one comes from the bootstrap variables at first start, and only when the user
table is empty — see [Installation](../getting-started/installation.md#the-first-account).
After that, both variables are ignored.

An account has an `is_active` flag. A deactivated account cannot sign in, and its history
stays intact — which is the point of deactivating rather than deleting one.

## Roles

Roles decide what a person can do. SUPERUSER is the role that can administer other
accounts, and it is the one to hand out sparingly: the audit log is only as meaningful as
the number of people who can change what it records.

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
