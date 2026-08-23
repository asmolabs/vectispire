# Exposed credentials and GitHub purge — what is left to do

This document exists because these two actions cannot be performed from the repository:
one means going and revoking a key at a provider, the other means opening a ticket with
GitHub. Everything else — the inventory, the checks, the commands — is prepared here.

**Context.** `zanshin/database.sqlite` was committed for months. It held the password
hashes and the "encrypted" private SSH keys — encrypted with a default key that was itself
published in the repository. The history was rewritten and force-pushed on 2026-08-06, but
a force-push does not delete the objects on GitHub's side: they become unreferenced and
stay reachable by their hash until a server-side purge.

**The repository is private.** That greatly reduces the exposure — only accounts that had
access to the repository could clone — without cancelling it: anyone or any token that had
that access could have retrieved the database, and revoking access afterwards changes
nothing.

---

## 1. Rotation — in order of urgency

### 1.1 The `perso` SSH deployment key — critical

Observed on the current database: the key named `perso`
(`ae2088e9-e958-40a6-afe2-0cf2de2d3d60`, created 2026-07-29) is an **RSA private key**
encrypted with the default key `my-secret-encryption-key-32bytes` — a constant that was
published in this repository's source code.

In other words: anyone who obtained a copy of the old `database.sqlite` holds that private
key in clear text. It must be considered compromised.

**What the code does now.** That constant has been removed from
[`EncryptionService`](../zanshin-java/zanshin-core/src/main/java/com/asmolabs/zanshin/core/services/EncryptionService.java):
the application no longer carries the key that opens its own database, and the value above
is no longer tried during decryption. The `perso` row therefore shows as **"Unreadable"**
on the *SSH keys* page — that is the expected result, and the replacement below is the only
correct follow-up: re-saving the same content under a real `ENCRYPTION_KEY` would achieve
nothing, since its private half is already public.

If you need to read it one last time (to identify which provider to revoke it at, for
instance), supply the old key explicitly, for the duration of the operation:

```bash
ZANSHIN_PREVIOUS_ENCRYPTION_KEYS="<your-previous-key>" cd zanshin-java && ./gradlew :zanshin-core:bootRun
```

To do, **in this order**:

1. **Revoke** the corresponding public key at the git provider (GitHub: *Settings → SSH and
   GPG keys* for an account key, or *Repo → Settings → Deploy keys*). Revocation comes
   before generation: it is what stops the access.
2. **Generate** a new pair:
   ```bash
   ssh-keygen -t ed25519 -C "zanshin-deploy" -f ~/zanshin-deploy
   ```
   Ed25519 rather than RSA: shorter, and it is the recommended default today.
3. **Set `ENCRYPTION_KEY`** in Zanshin's environment *before* saving the new key —
   otherwise the application refuses to encrypt (that is the safeguard in place, and it is
   doing exactly its job here):
   ```bash
   openssl rand -base64 32
   ```
   That value goes into the service's environment, not into the repository.
4. **Replace** the key from the *SSH keys* page. Saving encrypts it with the new
   `ENCRYPTION_KEY` and binds it to its row (associated data), so the old ciphertext is no
   longer replayable elsewhere.
5. **Delete** the old `perso` entry, since its content is public in effect.

### 1.2 The `admin` account's password

That account's bcrypt hash was in the committed database. bcrypt holds up well, but an
exfiltrated hash is a password with a limited lifetime, not a protected password.

The mechanism is already there: setting `must_change_password` to true forces the change at
the next login, without blocking access. That flag is currently **false** for `admin`. An
administrator can trigger it from the *Users* page (resetting the password sets it
automatically), or in one query:

```sql
UPDATE t_user SET must_change_password = 1;
```

### 1.3 The bootstrap password

If `ZANSHIN_BOOTSTRAP_PASSWORD` was filled in a compose file, an environment file or a CI
variable, it must be changed there too — and it is now provisional by construction: the
account created with it has to change its password at first login.

### 1.4 Nothing else to do on the settings side

Verified: the `setting` table currently holds **no** credential
(`notification_webhook_url` is empty, no `ticket_token`, no `local_scan_api_token`). If any
of those settings was filled in before 2026-08-06, it was in the committed database and
must be rotated — a Slack or Teams webhook token is a bearer secret, even though it looks
like a URL.

### 1.5 The agent keys are not affected

Since distributed scanning arrived, an agent authenticates with an API key carrying the
`agent` scope and nothing else. Those keys were created after the exposure, so **none of
them needs rotating here** — the note is here so the question does not come up again. They
are revoked from the *API keys* page like any other, and an agent that loses its own can no
longer claim work: it holds neither database access nor `ENCRYPTION_KEY`, which is
precisely what limits the consequences of a compromised agent.

### 1.6 Rotating `ENCRYPTION_KEY` itself

Useful beyond this incident, and impossible until now: changing `ENCRYPTION_KEY` made every
stored secret unreadable at once, and the documented procedure was to re-enter each value
by hand.

```bash
ENCRYPTION_KEY="<new key>" \
ZANSHIN_PREVIOUS_ENCRYPTION_KEYS="<old key>" \
cd zanshin-java && ./gradlew :zanshin-core:bootRun
```

The old key is used **for decryption only**: every write goes under the new one. Values
therefore migrate as they are re-saved, and the *SSH keys* page shows **"To rotate"** as
long as a row still depends on the old one — the old key comes out of the environment when
no row shows it any more. Several previous keys can be listed, comma-separated, for an
interrupted rotation.

**In production both halves belong in files, not on that command line.** `ENCRYPTION_KEY_FILE`
and `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS_FILE` take paths — a Docker or Kubernetes secret mount —
and keep the two keys out of `/proc/<pid>/environ`, `docker inspect`, the orchestrator's logs and
this shell's history. The second variable exists precisely for this moment: a rotation is when two
keys are live at once, and without it the old key — which still decrypts real rows — would have to
go back into the environment to finish a rotation whose whole point was getting the new one out of
it. The file holds the same list, comma- or newline-separated, one key per line being the readable
form once it is no longer squeezed onto a shell line.

Setting a variable *and* its `_FILE` form together is refused at startup rather than ranked, so
the migration from one to the other is finished when you think it is. And a path that does not
resolve stops the application instead of starting with no key — which matters here more than
anywhere, because a deployment with no key goes on reading everything it stored and only refuses
new writes: mid-rotation, that reads exactly like success.

---

## 2. Purging unreferenced objects at GitHub

### 2.1 First check whether it is still needed

From an authenticated session (`gh auth login`), an old SHA from before the rewrite — for
instance `92df73d`, `7e78c14`, `e934b76`, `54bf480`, `bdd5795`:

```bash
gh api repos/Asmo1973/Zanshin/commits/92df73d --jq .sha   # 404 = purged, 200 = still served
```

Or in a browser: `https://github.com/Asmo1973/Zanshin/commit/92df73d`. If the page renders,
the object is still there.

These commands could **not** be run conclusively here: `gh` is not authenticated on this
machine and the repository is private, so the 404s obtained mean nothing. To be redone on
your side before writing to GitHub.

### 2.2 Check for forks

A fork keeps the objects independently, and that is the usual reason a purge is refused. To
check:

```bash
gh api repos/Asmo1973/Zanshin --jq '{forks: .forks_count, network: .network_count}'
```

If a fork exists, it must be deleted before the purge, otherwise the operation achieves
nothing.

### 2.3 The message to send

Through <https://support.github.com/request> (category *Repository / other*):

> Hello,
>
> The private repository `Asmo1973/Zanshin` mistakenly contained a SQLite database file
> (`zanshin/database.sqlite`) holding secrets: password hashes and a private SSH key. The
> history was rewritten with `git filter-repo` and force-pushed on 6 August 2026, and the
> `main` branch no longer contains that file.
>
> Commits from before the rewrite remain reachable by their hash (for example `<full
> SHA>`), however, because a force-push does not delete objects that have become
> unreferenced.
>
> Could you run a garbage collection on this repository so that these objects are no longer
> served? There is no fork to my knowledge.
>
> Thank you.

Two details that speed up handling: give at least one **full SHA** (40 characters) of a
commit from before the rewrite, and explicitly confirm the absence of forks. The short SHAs
above are no longer available in full form from this machine — the local history was
replaced — but they can be found in the GitHub notifications received at the time, in an
old clone, or in your shell history (`grep -r 92df73d ~/.zsh_history`).

### 2.4 What the purge does not do

It stops GitHub from continuing to serve those objects. It does not recover what has
already been cloned. **The rotation in section 1 remains necessary whatever the outcome**,
and it is the part that counts: the purge closes a door, the rotation invalidates what went
through it.
