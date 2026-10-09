# Incident note: credentials committed in a development database (August 2026)

*Written up in October 2026 from the project's records of August 2026. It replaces an earlier
working note that listed the follow-up actions.*

## What was exposed

A development SQLite database file was committed to the project's earlier repository, which was
private, and stayed in its history for several months. It held:

- the password hashes (bcrypt) of the local accounts;
- a deployment SSH private key, stored "encrypted" — but with a **default encryption key that was
  itself a constant in the source code**, so anyone holding the file could decrypt it.

The settings stored in the same file could have held a notification webhook or a tracker token; none
was set when this was checked in August 2026, and any set earlier was in the file too. Agent keys
were introduced after the exposure and were never in it.

## When and how

- The file was committed in the course of development, while SQLite was the only database.
- How it was noticed is not recorded. It was removed on **6 August 2026** — the day the database
  layer was made configurable beyond SQLite — by rewriting the history and force-pushing it.
- A force-push does not delete the objects on the forge: commits from before the rewrite stay
  reachable by their hash until the forge purges them. The exposure was therefore bounded by who
  had access to that private repository, not closed by the rewrite.

## What was done

- **The exposed credentials were declared compromised**, and the follow-up set out: revoke the
  deployment key at its forge and replace it, force a password change on the local accounts, and
  rotate any setting that held a credential. Revoking at the provider is the step that matters; a
  purge on the forge closes a door, a rotation invalidates what went through it. Those steps happen
  outside the repository, and their completion is not recorded in it.
- **The history was rewritten** (6 August 2026) and a server-side purge of the unreferenced objects
  of the old repository was requested from the forge.
- **The current repository is a new one**, created on 27 August 2026, not a rename of the old one.
  Checked on 30 August 2026: none of the old commits is present in it, no object in its history
  matches a database or key file, and a gitleaks scan over its full history found nothing.

## What changed in the project

- **The default encryption key is gone.** The application no longer carries a key that opens its
  own database: without `ENCRYPTION_KEY` (or Vault Transit) it refuses to store a new secret
  rather than encrypt it with a known value, and the old constant is not tried on decryption. A
  value encrypted with it reads as *unreadable* until it is replaced. Rotating the key itself is
  documented in [`KEY_ROTATION.md`](../../en/KEY_ROTATION.md).
- **Database files cannot be committed by accident**: `*.db` and `*.sqlite*` are ignored, and the
  database is a server (MySQL or PostgreSQL) configured by the environment.
- **The bootstrap password is provisional**: the account it creates must change it at first login.
- **Every push and pull request runs gitleaks over the whole history** (the `secrets` job of
  `.github/workflows/ci.yml`, `fetch-depth: 0`). Known, judged-harmless hits are pinned one by one
  in `.gitleaksignore` rather than allow-listed by pattern. That job read no commit at all from
  25 August to 3 October 2026 while reporting success — git refused the checkout's ownership inside
  the container — and now fails a scan that read nothing or logged an error.

## What remains true

- Whatever was cloned from the old repository before the rewrite cannot be recalled. Only the
  rotation makes it worthless.
- Whether the forge completed the purge of the old repository is not recorded here; it concerns the
  old repository only, which the current one does not descend from.
- An ignore rule or a scanner reduces the chance of a repeat; none of them makes a
  committed secret safe. A secret that reached a repository is revoked, not cleaned.
