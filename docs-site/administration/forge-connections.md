# Forge connections

A read-only connection to a GitHub or a GitLab, from which Vectispire will discover your repositories and
let you choose the ones to import ([decision 0037](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0037-discovering-repositories-at-setup.md)).
This release ships the connections themselves: the discovery and the import come in the next lots, and
until then a connection proves that its token works and reads what it should.

Administrators only, through `/api/v1/forge-connections` ([API reference](https://github.com/asmolabs/vectispire/blob/main/docs/en/api/rest_api_reference.md)).
There is no screen yet.

## What a connection is

A name, a forge (`github` or `gitlab`), its **web address** — the one in your browser's address bar,
`https` only — and a token. Leave the address blank for github.com or gitlab.com. For GitHub, also the
**owner**: the organisation or user the token was issued for.

| You run | Address to type | API reached |
|---|---|---|
| gitlab.com | *(blank)* | `https://gitlab.com/api/v4` |
| GitLab self-managed or Dedicated | `https://gitlab.example.org` (a path prefix such as `/gitlab` is kept) | `…/api/v4` |
| github.com | *(blank)* | `https://api.github.com` |
| GitHub Enterprise Cloud with data residency | `https://acme.ghe.com` | `https://api.acme.ghe.com` |
| GitHub Enterprise Server | `https://github.example.org` | `…/api/v3` |

Do not type the API's address: `…/api/v4` is refused with the address to type instead.

**The connection's token never clones.** Clone credentials stay the [SSH keys](ssh-keys.md) and HTTPS
tokens you already manage, chosen per host at import: the discovery token is read-only, stays in the
control plane, and is never sent to an agent.

## The token to create

| Forge | Create | Grant |
|---|---|---|
| GitLab | a **group access token** — a bot member that outlives the person who made it — or a personal access token; role **Reporter** on the groups to discover | **`read_api`** only |
| GitHub (github.com, ghe.com, Enterprise Server that offers them) | a **fine-grained** personal access token, resource owner = the connection's owner, repository access *All repositories* or a selection | **Metadata: read**, and nothing else |
| GitHub Enterprise Server without fine-grained tokens | a classic personal access token | `repo` (to list private repositories) and `read:org` |

**GitLab: `read_api`, and only read scopes.** The token is accepted with `read_api` plus, at most,
`read_repository`, `read_registry` or `read_user`. Anything else — `api`, `write_repository`, `sudo`,
`admin_mode`, the runner and Kubernetes scopes, and any scope GitLab adds later — refuses the connection:
the list is an allow-list. The connection shows whether the token is a group or project access token
(`gitlab_bot`) or a person's (`gitlab_personal`); prefer the first.

**GitHub fine-grained tokens: Vectispire cannot check their permissions.** GitHub does not report them
through its API. The connection shows `scopes: null` and `canWrite: null` — *unknown*, not *read-only*.
Grant **Metadata: read** only; that is a sentence, not a check.

**GitHub classic tokens are accepted on Enterprise Server only, and flagged.** On github.com and ghe.com
a classic token is refused: the only classic scope that lists private repositories, `repo`, can also
write to every one of them, and a fine-grained token is always available there. On Enterprise Server a
classic token holding `repo` or `public_repo` is accepted and shown **`canWrite: true`** — in the list,
the audit entry and the SIEM event. Administration scopes (`admin:org`, `delete_repo`, `workflow`, the
package scopes…) are refused.

**What remains, written rather than hidden.** A GitHub Enterprise Server classic `repo` token can write.
GitLab's `read_api` can also read files through the API. The connection is a standing read access to the
list of an organisation's repositories, held by the control plane.

## Probed before it is kept

On creation, and whenever the token or the way it is presented changes, Vectispire presents the token to
the forge once and reads what the forge says about it:

- **GitLab**: `GET /api/v4/personal_access_tokens/self` (scopes, expiry, revoked), `GET /api/v4/version`
  (**GitLab 16 or later**), `GET /api/v4/user` (bot or person). A token holding a refused scope is not
  presented a second time.
- **GitHub**: `GET /users/{owner}` — the scopes of a classic token, the token's expiry and, on
  Enterprise Server, its version (**3.12 or later**) arrive as headers. A 404 means the owner does not
  exist or is hidden from this token.

A refusal says why in words: token rejected or expired, `read_api` missing, a refused scope, a server too
old, an unknown owner, or an address that cannot be reached.

## On your internal network, behind your own CA

A self-managed GitLab or a GitHub Enterprise Server on the internal network is the common case.

- **Say so: tick *internal network*** (`internalNetwork: true`). Without it the address must be public:
  an address resolving to a private or local range is refused **before anything is sent**, and the
  refusal is recorded and signalled to the SIEM (`VECTI-SEC-036`) — a base URL aimed inward is how a
  server-side request forgery through this form would look. With it, private addresses are accepted;
  link-local addresses (the cloud metadata endpoint), Vectispire's database and its Docker daemon stay
  refused whatever you tick. The address is checked again at every request, since a name may resolve
  elsewhere tomorrow.
- **Pin your CA** (`caPem`): paste the CA that issued the server's certificate, in PEM. It must be a CA
  (a server's own certificate is refused), currently valid, and at most eight certificates. It is
  trusted **for this connection alone, instead of the public CAs**, and the server's certificate must
  still name the host you typed. There is **no "skip verification" switch** and there will not be one:
  the token would go to whoever answers first on the path.
- Neither applies to github.com, ghe.com or gitlab.com: their hosts are public and verified against the
  public CAs, and both are refused for them.

A CA that expires stops the connection; replace it with a `PATCH`, which probes the stored token again
through the new CA before keeping it.

## Rotation, changes and deletion

- **Replace the token in place** (`PUT …/token`): it is probed like a new one, and the connection keeps
  its identity and everything that will hang on it. A replacement the forge refuses leaves the stored
  token untouched. The expiry the forge reported is shown (`tokenExpiresAt`).
- **Rename, change the network statement or the CA** (`PATCH`). The address cannot change: another
  server is another connection.
- **Delete** (`DELETE`): no target goes with it — an imported repository is a target like any other.

## Encryption

The token is encrypted under `ENCRYPTION_KEY` with the row as its context, so a ciphertext copied into
another row does not decrypt. It is never returned by any route, written in the audit trail or logged.
`encryptionState` reads `previous_key` while a [key rotation](maintenance.md) has not reached the row:
**saving the connection** (any `PATCH`) or replacing its token re-seals it under the current key.

## Audit and SIEM

| Gesture | Audit | SIEM |
|---|---|---|
| Created, token replaced, network statement or CA changed, deleted | `FORGE_CONNECTION_CHANGED` | `VECTI-SEC-034` (6) |
| Renamed | `FORGE_CONNECTION_CHANGED` | — |
| Refused for a blocked address or a refused scope | `FORGE_CONNECTION_REFUSED` | `VECTI-SEC-036` (5, failure) |
| Refused for anything else — a mistyped token, an old server | — | — |

The entries name the forge, the address, the owner, the kind of token, its scopes and whether it can
write; never the token. See the [SIEM catalogue](../integrations/siem.md#event-catalogue).
