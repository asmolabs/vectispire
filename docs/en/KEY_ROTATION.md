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

The old key is used **for decryption only** — every write goes under the new one. Values migrate
as they are re-saved, and the *SSH keys* page shows **"To rotate"** as long as a row still depends
on the old one. **The old key comes out of the environment when no row shows it any more**, and not
before: removing it early leaves those rows unreadable with nothing to say so.

Several previous keys can be listed, comma-separated, which is what an interrupted rotation needs.

### The stores that show their state

Three stores say, row by row, which key they are sealed under (`encryptionState`: `current`,
`previous_key`, `unreadable`), and each is re-sealed by its own gesture:

| Store | Where the state shows | What re-seals a row |
|---|---|---|
| SSH deploy keys | the *SSH keys* page, `GET /api/v1/ssh-keys` | adding the key again and deleting the old row |
| HTTPS clone tokens ([0022](../architecture/en/decisions/0022-https-clone-tokens-are-bound-to-a-host.md)) | `GET /api/v1/git-tokens` | adding the token again and deleting the old row |
| Forge connections ([0037](../architecture/en/decisions/0037-discovering-repositories-at-setup.md)) | `GET /api/v1/forge-connections` | saving the connection (`PATCH /api/v1/forge-connections/{id}` — an empty `{}` will do) or replacing its token (`PUT …/token`) |

The rotation is finished when none of them lists a `previous_key` row.

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
