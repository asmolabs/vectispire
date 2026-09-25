# 0022 — Cloning over HTTPS uses a managed token, bound to one host

**Date:** 2026-09-25 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

Vectispire clones over SSH with managed deployment keys, and over HTTPS without credentials. A
private repository reachable only over HTTPS — the common case behind a corporate proxy, or on a
forge that issues personal or project access tokens rather than deployment keys — had one way in:
the token written into the URL, `https://user:token@host/project.git`.

That works and it is the wrong place for a secret. The URL is stored **in the clear** in
`t_repository.url`, next to rows whose other secrets are encrypted; it has to be masked on every
screen, message and audit line (`RepositoryUrl.redact` exists for that reason alone); and it
travels to whichever agent claims the scan, whatever that agent's credentials mode promised.

## Decision

**An HTTPS token is a managed credential, like a deployment key, and it is bound to one host.**

- A new store, `t_git_token`: a name, the **host** it is issued for, an optional user name, and the
  token encrypted with the row as its context (`SecretCipher`), so a ciphertext copied into another
  row does not decrypt. The token is never returned by any route.
- A repository references either an SSH key or an HTTPS token, never both, and the reference must
  match the URL: a token only for an `https://` URL **on the token's host**, a key only for SSH.
- **The token is presented to its host and to nothing else.** The clone supplies it through a
  credentials provider that answers only for that host, so a redirect to another host — or a
  repository URL somebody points elsewhere — receives no credential. Without the binding, attaching
  a forge token to a repository whose URL names another server would send the token there.
- It reaches the scan the way a deployment key does: decrypted by the control plane, handed only to
  an executor whose credentials mode is `delegated`, sealed to the agent's announced key, and
  refused by an agent that announced a sealing key if it arrives in the clear. A `local` agent
  receives no token, as it receives no key.
- **New credentials in a URL are refused** on entry, with a message pointing to the tokens screen.
  Existing URLs keep working — refusing them on upgrade would stop those scans without a word — and
  stay masked as before.

## Consequences

- One more encrypted store, one more screen, one more field on the repository form.
- The agent protocol gains an optional field on the repository target. An agent that predates it
  ignores the field and clones without credentials, which fails with "requires authentication" —
  visible, and fixed by upgrading the agent.
- A `local` agent cannot clone a private repository over HTTPS: JGit does not read git credential
  helpers, and the host's own configuration is SSH-only today. That is the same promise the mode
  makes for keys, and it is stated rather than worked around.
- Rotating a token is replacing it: the old row is deleted once no repository uses it, like a key.
