# Rotation and purge

## Rotating the encryption key

`ENCRYPTION_KEY` protects deploy keys and tracker tokens at rest. Rotating it is a
four-step operation with no downtime.

**1. Keep the old key readable.**

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-key-new
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE=/run/secrets/vectispire-keys-old
```

Previous keys are tried **for decryption only**. Never for writing.

**2. Restart.** Existing values decrypt with an old key; new writes use the new one.

**3. Re-save the secrets.** Values move to the new key as they are re-saved. The
[SSH keys](ssh-keys.md) page marks the rows that still depend on an old key — that marking
is how you know the rotation is finished rather than merely started.

**4. Remove the old key** from the previous-keys list once nothing is marked.

Do not skip step 4 indefinitely. A rotation that leaves the old key permanently readable
has changed which key is written and nothing else.

!!! warning "Keys that predate any ENCRYPTION_KEY"
    A value encrypted with the default that used to ship in this repository will show as
    unreadable. That default has been removed and **its private half is public**. Replace
    the key pair at your Git provider rather than trying to recover it.

## File over environment

`ENCRYPTION_KEY_FILE` rather than `ENCRYPTION_KEY`, in production, always. It keeps the
value out of `/proc/<pid>/environ`, `docker inspect` and your orchestrator's logs, and it
is what a Docker or Kubernetes secret mounts natively.

Setting both is refused. A path that does not resolve stops the application rather than
starting with no key — a start that silently proceeded without one would refuse every
secret write hours later, somewhere unrelated.

## Retention and purge

Scans accumulate: normalised findings, plus the raw SBOM and matcher output kept for audit.
Retention is configured under [Settings](settings.md).

Two things to weigh:

**The raw blobs are the bulky part.** They are also the evidence somebody needs to
re-derive your conclusions rather than take them on trust.

**Purging a scan does not purge the issue.** Issues track problems across scans and carry
their own history and triage decisions. The record of what was decided survives the record
of the run that first observed it.

## Before deleting a target

Removing a repository or image removes its scans and issue history with it. Export the
[detection and triage history](../guide/history.md) first where that record has to survive
— it is written precisely for the reader who was not there.
