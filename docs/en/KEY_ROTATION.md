# Rotating `ENCRYPTION_KEY`

*Version française : [`docs/fr/KEY_ROTATION.fr.md`](../fr/KEY_ROTATION.fr.md).*

`ENCRYPTION_KEY` decrypts everything Vectispire keeps sealed: the deployment keys attached to
repositories, the credentials for container registries, ticketing tokens, the sealed envelopes an
agent opens. Rotating it is therefore an operation on live data, and this page is the procedure.

> **Why this page exists separately.** The procedure used to live inside
> the working note of a specific credential exposure in August 2026, now replaced by an
> [incident note](../analysis/en/2026-08-06_credential_exposure_incident.en.md). Somebody looking for "how do I rotate the key" opened an incident
> report and read the history of a leak. The account of the incident is kept apart, dated, and the
> reusable part is here.

## The rotation

Both keys are live at once: the new one for every write, the old one for reads that have not
migrated yet.

```bash
ENCRYPTION_KEY="<new key>" \
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS="<old key>" \
cd vectispire-java && ./gradlew :vectispire-core:bootRun
```

The old key is used **for decryption only** — every write goes under the new one. **The old key
comes out of the environment when no sealed store depends on it any more**, and not before:
removing it early leaves those values unreadable — second factors refused at sign-in, nothing
signed, the SIEM's authorization header dropped — with nothing to say so.

Several previous keys can be listed, comma-separated, which is what an interrupted rotation needs.

### Where the rotation stands: `/actuator/encryption`

One report, to an administrator's session, lists every store Vectispire keeps sealed and how many
of its values stand under the current key, under a previous one, under none (`unreadable`), or in
the clear because they predate encryption:

```bash
curl -s -H "Authorization: Bearer <an administrator's session>" https://vectispire.example.com/actuator/encryption
```

**The rotation is finished when it answers `"rotationFinished": true`** — no store has a
`previousKey` above zero. Until then, every start also logs a warning per store that still
depends on a previous key, naming what re-seals it. The report says how many values stand where,
never what they hold.

| Store | What re-seals a value still under a previous key |
|---|---|
| SSH deploy keys | adding the key again, moving the repositories to it, deleting the old row (the *SSH keys* page and `GET /api/v1/ssh-keys` show each row's state) |
| HTTPS clone tokens ([0022](../architecture/en/decisions/0022-https-clone-tokens-are-bound-to-a-host.md)) | adding the token again, moving the repositories to it, deleting the old row (`GET /api/v1/git-tokens`) |
| Forge connection tokens ([0037](../architecture/en/decisions/0037-discovering-repositories-at-setup.md)) | saving the connection (`PATCH /api/v1/forge-connections/{id}` — an empty `{}` will do) or replacing its token (`PUT …/token`) |
| Document signing key | the next start, by itself |
| TOTP secrets and backup codes | the account's next second-factor check — a sign-in, or disabling — by itself; or enrolling again |
| Tracker access token, inbound tracker webhook secret | setting it again on the ticketing settings (and, for the webhook secret, in the tracker) |
| Notification webhook signing secret | setting it again on the notification settings, and in the receiver |
| OpenAI API key | setting it again on the model review settings |
| SIEM authorization header | setting it again on the SIEM settings |

## In production, both halves belong in files

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-key
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE=/run/secrets/vectispire-previous-keys
```

A Docker or Kubernetes secret mount, and the keys stay out of `/proc/<pid>/environ`,
`docker inspect`, the orchestrator's logs and this shell's history. The second variable exists
precisely for this moment: a rotation is when two keys are live at once, and without it the old
key — which still decrypts real rows — would have to go back into the environment to finish a
rotation whose whole point was getting the new one out of it.

The file holds the same list, comma- or newline-separated; one key per line is the readable form
once it is no longer squeezed onto a shell line.

**Setting a variable and its `_FILE` form together is refused at startup rather than ranked**, so
the migration from one to the other is finished when you think it is. And a path that does not
resolve stops the application instead of starting with no key — which matters here more than
anywhere: a deployment with no key goes on reading everything it stored and only refuses new
writes. Mid-rotation, that reads exactly like success.

## What a rotation does not cover

- **The audit chain** is hashed, not encrypted. Rotating the key neither breaks nor re-seals it.
- **Agent keys** are their own credentials, revoked and reissued from the agents page.
- **Passwords** are Argon2id hashes and do not involve this key at all; they are rewritten under
  current parameters on the account's next sign-in.
- **A backup taken before the rotation** still needs the key that was current when it was taken.
  A snapshot and the key that opens it are two artefacts: keep them apart, and keep the old key
  for as long as any backup you would still restore was written under it.
  [Backup and restore](BACKUP_AND_RESTORE.md) says how the two are taken, kept and restored
  together.

# Rotating the document signing key

The **document signing key** is another key, and rotating `ENCRYPTION_KEY` does not touch it. It
signs what Vectispire hands to people outside it — evidence bundles, VEX, CSAF and CycloneDX
exports, checklist sign-offs, project exports and the provenance of report documents — and
consumers verify those against the public half Vectispire publishes. Rotating it changes what
those consumers must trust, so the procedure is mostly about them.

It comes from one of two places: `vectispire.signing.key` (a P-256 PKCS#8 PEM: `VECTISPIRE_SIGNING_KEY`
in the composition's `.env`, `secrets.signingKey` in the chart), or, when that is empty, a key
Vectispire generated on first use and keeps in `t_setting`, sealed under `ENCRYPTION_KEY`.

## What happens to the documents signed before

**They remain verifiable.** Every public key this deployment has signed with is recorded — public
halves only, in the clear, in `t_setting` (`internal.document_signing_keys`) — and published:

| Route (no account needed) | Answers |
|---|---|
| `GET /api/v1/crypto/public-key.pub` | the **active** key, as before |
| `GET /api/v1/crypto/public-keys` | every key: `keyId`, `status` (`ACTIVE`, `RETIRED`, `REVOKED`), `publicKey` (PEM), `activeFrom`, `retiredAt` |
| `GET /api/v1/crypto/public-keys/<keyId>.pub` | one of them, as the PEM `cosign verify-blob --key` reads |

A key id is the SHA-256 of the key's DER encoding, in hex. A document names the key that signed it:
a DSSE envelope's `keyid`, the key carried beside an evidence bundle (for convenience only — compute
its id, then fetch that id from the instance), the `signing_key_id` a checklist document and a report
run record. `POST /api/v1/crypto/verify` tries the active key, then the retired ones, and says which
matched (`keyId`, `keyStatus`).

**The record starts on the first start of a version that has it (1.0.0).** A key replaced before
that is not in it. Start once on 1.0.0 with the key you have, check it is listed as `ACTIVE`, and
only then rotate.

## The rotation

Executed every night, as written here, by `scripts/signing-key-rotation-drill.sh` against the image
that ships: an evidence bundle signed before the rotation is verified with openssl against the key
published under its id, and one signed after against the active key.

**1. Generate the new key**, where it will be kept:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out vectispire-signing-key.pem
```

**2. Note the key in use**, to recognise it afterwards:

```bash
curl -s https://vectispire.example.com/api/v1/crypto/public-keys
```

**3. Configure the new key and restart.** With the composition, put the PEM in `.env` as
`VECTISPIRE_SIGNING_KEY` (it reaches the container as a file); with the chart, `secrets.signingKey`;
otherwise `vectispire.signing.key`, or a file of that name in the directory
`SPRING_CONFIG_IMPORT=configtree:` reads. A configured key always takes precedence over the stored
one. With several instances, restart them all: until the last has restarted, the old ones still
sign with the old key, and those signatures verify as a retired key's.

**While instances restart one by one**, every instance publishes the same list: the statuses are the
record's, written by the first instance to sign with the new key. From then on `public-key.pub`
serves the new key from every instance, while an instance not yet restarted goes on signing with
the old one — so a document signed in that window names the old key, verifies against
`public-keys/<keyId>.pub` as a retired key's, and its `retiredAt` can precede its signature. A
retired key is not a revoked one: what it signed remains authentic, whenever. An instance not yet
restarted never takes the record back, even when it signs for the first time after the rotation.
Finish the restarts before telling the consumers (step 5).

**4. Check.** The same request now lists the new key `ACTIVE` and the previous one `RETIRED`, with
the date it was replaced. When the previous key was the generated one, it is listed as well: it is
the key every document so far was signed with.

**5. Tell the consumers.** Anybody who pinned `public-key.pub` must fetch it again; anybody verifying
an older document fetches the key it names from `public-keys/<keyId>.pub`. Consumers are better
served by the list than by a single key: it is what lets them check a document from before a
rotation without asking you which key it was.

**6. The old private key.** Verification needs only the public half, which Vectispire keeps. A
configured key's file can be destroyed once you will not roll back; removing `vectispire.signing.key`
again makes the stored key — or a newly generated one, if there was none — the active one, and the
key it replaces is retired in turn. A generated key stays sealed in `t_setting` and keeps appearing
in `/actuator/encryption`; it signs nothing while a key is configured.

## When the key is compromised

Rotate as above, and list the compromised key's id in `vectispire.signing.revoked-keys`
(`VECTISPIRE_SIGNING_REVOKED_KEYS`, comma-separated) on every instance:

- it stays published, `status: REVOKED`, so a consumer learns why a document no longer verifies;
- `POST /api/v1/crypto/verify` answers `valid: false` for a signature it made, even one that
  matches: whoever holds it can sign anything;
- an instance whose signing key is revoked refuses to start, and says so: a configured key, or the
  generated one when no key is configured. A generated key that cannot be read (`ENCRYPTION_KEY`
  lost) signs nothing either way, and is refused at the first signature with that reason.

Then re-issue the documents that still matter — export them again — and say to their recipients
which ones replace which. A revocation is only as good as the consumers who check the list, which is
another reason to point them at it rather than at a single file.

## With `ENCRYPTION_KEY`

The two rotations are independent; do them one at a time, so that each one's report says what it
is about.

- **Rotating `ENCRYPTION_KEY`** re-seals the generated signing key at the next start, and
  `/actuator/encryption` counts it as *Document signing key*. The signing key itself does not
  change, and no consumer notices.
- **Losing `ENCRYPTION_KEY`** makes a generated signing key unreadable: signing is refused rather
  than a new key improvised. Configure a new signing key: that is a rotation. The published keys are
  not sealed, so the documents signed before stay verifiable even though the key that signed them
  is lost.
- **The record of public keys is not a secret** and is not in `/actuator/encryption`. It is in the
  database, and so in every dump: a restore brings back the keys that were published when it was
  taken.
