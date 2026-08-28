# API keys

Issued from the interface, for machines rather than people. A CI gate authenticates with
one; so does a remote agent.

## Scopes

A key carries a scope, and the scope is the whole security story. The `agent` scope is the
one to understand: it lets a process poll for jobs and post results, and **nothing else** —
in particular, no database access.

Give a CI gate a key that can ask for a verdict. It does not need one that can register
targets.

## Shown once

A key is displayed once, at creation. Vectispire stores what it needs to verify a
presented key and cannot show you the value again.

Put it straight into your secret store. If it is lost, revoke it and issue another — that
is a two-minute operation, and a key pasted into a chat window to avoid it is a permanent
one.

## Authentication headers

| Header | For |
|---|---|
| `Authorization: Bearer …` | a user session (JWT) |
| `X-API-Key` | an API key |
| `X-Agent-Key` | a remote agent |

## Revoking

Revoke a key when the pipeline that used it is retired, when someone who could read it
leaves, or when you are not sure. Revocation is immediate, and every use is in the
[audit log](audit-log.md).

## In CI

```yaml
env:
  VECTISPIRE_API_KEY: ${{ secrets.VECTISPIRE_API_KEY }}
```

Never in the repository, never in the job definition. See
[CI policy gate](../integrations/ci-gate.md).
