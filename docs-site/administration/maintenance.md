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

**3. Re-seal the secrets.** Values move to the new key as they are re-saved; the signing key and
the second factors move by themselves, at the next start and at each account's next
second-factor check. `/actuator/encryption` — an administrator's session — lists every sealed
store, how many of its values still depend on an old key, and what re-seals them: that report,
not one page, is how you know the rotation is finished rather than merely started. Every start
also logs the stores that still depend on one.

**4. Remove the old key** from the previous-keys list once the report answers
`"rotationFinished": true`.

Do not skip step 4 indefinitely. A rotation that leaves the old key permanently readable
has changed which key is written and nothing else.

!!! warning "Keys that predate any ENCRYPTION_KEY"
    A value encrypted with the default that used to ship in this repository will show as
    unreadable. That default has been removed and **its private half is public**. Replace
    the key pair at your Git provider rather than trying to recover it.

## Rotating the document signing key

The key that signs evidence bundles, VEX, CSAF and CycloneDX exports, checklist sign-offs and
report provenance is not `ENCRYPTION_KEY`, and the rotation above does not change it.

**1. Generate the new key:** `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out vectispire-signing-key.pem`.

**2. Configure it and restart every instance:** `VECTISPIRE_SIGNING_KEY` in the composition's
`.env`, `secrets.signingKey` in the chart, `vectispire.signing.key` otherwise. A configured key
takes precedence over the one Vectispire generated.

**3. Check** `GET /api/v1/crypto/public-keys` (no account needed): the new key `ACTIVE`, the previous
one `RETIRED` with the date it was replaced.

**4. Tell the people who verify your documents.** Documents signed before the rotation still
verify: each names its key, and `GET /api/v1/crypto/public-keys/<keyId>.pub` serves it.
`public-key.pub` now serves the new key.

The record of published keys starts on the first start of 1.0.0: start once on it before rotating.
A **compromised** key also goes into `VECTISPIRE_SIGNING_REVOKED_KEYS` (its id): it stays published
as `REVOKED`, and nothing signed with it verifies. The full procedure, and how it meets an
`ENCRYPTION_KEY` rotation, is in [`docs/en/KEY_ROTATION.md`](https://github.com/asmolabs/vectispire/blob/main/docs/en/KEY_ROTATION.md#rotating-the-document-signing-key).

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

**Evidence has a window of its own**, *Evidence kept for (days)* (`evidence_retention_days`,
400 days by default; zero keeps it for ever): the gate's verdicts, the monthly compliance captures,
the weekly OWASP record, and, for each [report](report-plugins.md#requesting-a-report) produced, the
export it was given and the signed document it produced. Only those bytes go: the report run itself
stays, with the digests of its export, its document and its package. Unlike a payload none of it can be regenerated, so set it to the
period an assessor asks you to cover plus the delay before they read it, and not to the payload
window. Only a platform governor changes it: a CISO or an administrator could set it to a day, and the
next turn purged the record of every control they run. The hourly maintenance turn purges what has left it. A week of the OWASP record is kept
while any of it is still inside the window; once purged, the *By week* view shows it as it shows
the weeks before the record began — reconstructed from the issues' dates, with no recorded state.

**Purging a scan does not purge the issue.** Issues track problems across scans and carry
their own history and triage decisions. The record of what was decided survives the record
of the run that first observed it.

## Before deleting a target

Removing a repository or image removes its scans and issue history with it. Export the
[detection and triage history](../guide/history.md) first where that record has to survive
— it is written precisely for the reader who was not there.
