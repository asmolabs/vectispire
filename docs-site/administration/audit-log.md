# Audit log

An immutable, hash-chained record of what was done and by whom.

## Why a chain

Each entry is chained to the one before it, so an entry cannot be altered or removed
without breaking the chain from that point on.

A plain audit table records what happened, provided nobody with database access wanted it
to say something else. A chain makes tampering **evident**, which is a materially different
claim — and it is the claim an auditor, an insurer or a customer's security team is
actually asking about.

The verification screen checks the chain and tells you where it breaks.

## The mirror

```bash
VECTISPIRE_AUDIT_MIRROR=/var/log/vectispire/audit.jsonl
```

Each entry is appended as one JSON line, **outside the database it watches**.

That is what closes the remaining gap. A chain inside the database detects tampering by
anyone who cannot rewrite the whole chain; a second copy outside it detects tampering by
someone who can. Point it at a path shipped to a log store you can append to but not edit.

Off means the log has one copy — and the verification screen says so, rather than implying
a guarantee it cannot make.

## What to check, and when

- After any unexpected privilege change.
- Before exporting [compliance evidence](../guide/compliance.md).
- On a schedule, so the answer is not first sought on the day it matters.

## Related

[Users and teams](users-and-teams.md) · [History and evidence](../guide/history.md) — the
triage record, which is a different document for a different question.
