# 0037 — Repositories are discovered through a read-only forge connection, chosen by a person, and imported as ordinary targets

**Date:** 2026-10-03 · **Status:** accepted · **Builds on:** [0002](0002-the-database-carries-the-queue.md), [0022](0022-https-clone-tokens-are-bound-to-a-host.md), [0023](0023-solutions-projects-and-repositories.md), [0025](0025-siem-events-leave-through-the-outbox.md), [0030](0030-modulith-verifies-the-module-boundaries.md) · **Decider:** Laurent Boucher

*Accepted on 2026-10-03 by the product owner, every open question settled as recommended — the
answers are at the end, under "Decided on 2026-10-03", and the body below is written as decided.
Bitbucket is the lot after the first (D8); v1 is GitHub and GitLab.*

## Context

The product owner's request, on 2026-10-03: *initialise the tool by finding the projects in GitLab,
GitHub and Bitbucket, and let me select the ones I want.*

Today a repository becomes a target in one way: an administrator fills in a form — URL, branch,
credential, schedule — and `RepositoryAdministrationService` creates one row
(`@RequiresAdministrator` on `POST /api/v1/repositories`). An estate of three hundred repositories
is three hundred forms, and nothing tells the administrator which repositories they have not yet
added. The first week of an installation is spent typing URLs, and the coverage it ends with is
whatever the typist remembered. A posture tool that only sees what somebody thought of declaring is
measuring the declaration, not the estate.

What already exists, and what this decision builds on:

- **Clone credentials** are managed: SSH deployment keys, and HTTPS tokens bound to one host
  ([0022](0022-https-clone-tokens-are-bound-to-a-host.md), `t_git_token`), both encrypted under
  `ENCRYPTION_KEY` with the row as context (`SecretCipher`), never returned by a route, handed only
  to an executor in `delegated` mode, sealed to its key.
- **One door to the outside**: `OutboundUrlGuard` resolves the destination and refuses it by policy
  (`PUBLIC_ONLY`, `INTERNAL_ALLOWED`, `INTERNAL_REQUIRED`; link-local and Vectispire's own reserved
  endpoints under every policy); `PinnedHttpSender` connects to the address that was checked and to no
  other; `OutboundJson` refuses redirects and bounds every call to ten seconds.
- **A forge API is already called** with an encrypted token: the ticketing integration
  (`TicketService`) opens issues on GitLab and GitHub, trims the base URL, and chooses its policy from
  an administrator's setting (`TICKET_ALLOW_PRIVATE_URL`: internal destinations allowed or not). It is
  the precedent for the base URL and for the policy.
- **Solutions contain projects, a project references repositories**, a grant may name a project and is
  resolved at each request ([0023](0023-solutions-projects-and-repositories.md)). A repository may be
  in no project; nothing is ever inferred into one without a person.
- **The scan queue is a table** ([0002](0002-the-database-carries-the-queue.md)), and a scan carries a
  `not_before` (V48) the claim already honours.
- **A weekly default schedule** is being added in parallel: a target with no schedule of its own is
  scanned weekly, its slot spread by its id so that an estate does not start at the same minute.
- **`TargetDeleted`** is published by `targets` to every module that holds rows about a target.

What does **not** exist: a rule for *"the same repository"*. `RepositoryUrl.normalizeHost` compares
hosts, for 0022's binding; nothing compares repositories, and nothing today stops two targets from
naming the same URL. A bulk import without that rule would duplicate every repository an
administrator had already typed in. This decision has to introduce it (§4).

## Decision

### 1. Forges, editions and APIs

**REST everywhere, one adapter per forge behind one interface** (`ForgeClient`: probe the token, list
namespaces, list repositories, page by page). Each adapter is a few hundred lines of mapping; the job,
the snapshot, the selection and the import are written once.

| Forge | Edition | API | Base URL | In |
|---|---|---|---|---|
| GitHub | github.com | REST, `X-GitHub-Api-Version: 2022-11-28` | fixed: `https://api.github.com`, clone host `github.com` | v1 |
| GitHub | Enterprise Cloud with data residency | same | `https://api.<subdomain>.ghe.com`, from the subdomain typed | v1 |
| GitHub | Enterprise Server | same, at `/api/v3` | typed: the web address users browse, e.g. `https://git.example.org` | v1 |
| GitLab | gitlab.com | REST v4, `/api/v4` | fixed: `https://gitlab.com` | v1 |
| GitLab | Self-managed and Dedicated | same | typed, a path prefix kept: `https://example.org/gitlab` | v1 |
| Bitbucket | Cloud | REST 2.0 | fixed: `https://api.bitbucket.org/2.0`, clone host `bitbucket.org` | v1.1 (lot D8) |
| Bitbucket | Data Center | REST 1.0, `/rest/api/latest` | typed | v1.1 (lot D8) |

- **The base URL is the web address, not the API's**, and the adapter derives the API path. An
  administrator copies what is in the browser's address bar; asking for `…/api/v4` would be the first
  thing they get wrong. Trailing slashes are trimmed (as `TicketService` does), a URL carrying
  credentials is refused (`RepositoryUrl.carriesCredential`), and **`https` only**: a token sent over
  `http` on an internal network is still a token on the wire.
- **Supported versions are the ones the vendor still supports** at the time the lot lands — the
  adapters use no endpoint younger than GitLab 16, GHES 3.12 or Bitbucket Data Center 8. A creation
  that finds an older server (GitLab `GET /version`, GHES's `X-GitHub-Enterprise-Version` header,
  Bitbucket's `application-properties`) refuses with the version it found rather than failing later
  on a missing field.
- **GitLab and GitHub in v1, Bitbucket in the lot after.** Both are already spoken by the ticketing
  integration, and between them they cover the estates the product has been shown. Bitbucket is in this
  decision, not deferred out of it: its two editions share nothing but a name — Cloud's authentication
  changed under it in 2025–2026 (app passwords withdrawn in favour of scoped API tokens), and Data
  Center returns the default branch only through one call per repository — and it ships as its own lot
  (D8) against the same interface rather than delaying the other two.

*Rejected:* **GraphQL** (GitHub v4, GitLab's). It would fetch repositories and their languages in one
request, and that is its only advantage here. GitHub prices GraphQL by computed cost, which is harder
to bound than a request count; GHES and self-managed GitLab lag the cloud schema by versions an
installation does not control; Bitbucket has none, so a GraphQL path would be a second implementation
of the same listing. **A generic Git-hosting library** (one client for every forge): it would bring its
own HTTP stack, which is exactly what must not exist beside `PinnedHttpSender` (§3).

### 2. A forge connection: a read-only credential, kept like the others

A **forge connection** is a name, a forge kind, a base URL, **for GitHub the owner** (organisation or
user) the token was issued for, an optional user name (Bitbucket Cloud authenticates an API token with
the account's address), and a token. It lives in a new table, `t_forge_connection`.

**The scopes, per forge — the narrowest each forge offers:**

| Forge | Credential | Scopes required | Refused |
|---|---|---|---|
| GitHub (cloud, data residency, GHES that offer it) | fine-grained personal access token, resource owner = the connection's owner, repository access "All repositories" or a selection | **Metadata: read** — and nothing else | — (fine-grained permissions are not readable through the API; see below) |
| GHES without fine-grained tokens | classic personal access token | `repo` is the only classic scope that lists private repositories, and it writes | accepted only there, **flagged as able to write** — in the list, the audit entry and `VECTI-SEC-034`'s details |
| GitLab | **group access token** (preferred: a bot member that outlives the person who made it) or personal access token, role Reporter on the groups to discover | **`read_api`** | any scope outside `read_api`, `read_repository`, `read_registry`, `read_user` — `api`, `write_repository`, `sudo`, `admin_mode`, runner and Kubernetes scopes |
| Bitbucket Cloud | Atlassian API token with scopes, or a workspace access token | `read:workspace:bitbucket`, `read:project:bitbucket`, `read:repository:bitbucket` (names checked against Atlassian's list when lot D8 starts) | any `write:`, `admin:` or `delete:` scope where the response states them |
| Bitbucket Data Center | HTTP access token (project or personal) | permission **Project read** / **Repository read** | write and admin permissions |

- **Probed on creation and on every replacement.** The adapter calls the forge once with the token and
  reads what the forge says about it: GitLab's `GET /personal_access_tokens/self` (scopes and expiry),
  GitHub's `X-OAuth-Scopes` (classic) and `github-authentication-token-expiration` headers,
  Bitbucket's scope headers. **A scope the forge states and the table refuses refuses the connection**;
  an allow-list, not a deny-list, so a scope a forge adds next year is refused until somebody reads it.
  Where the forge states nothing — GitHub's fine-grained tokens — the screen says *"GitHub does not
  report this token's permissions; grant it Metadata: read only"*, which is a sentence, not a check, and
  is written as one.
- **Stored like every other secret**: encrypted under `ENCRYPTION_KEY`, the row as its context
  (`forge-connection:<id>`), so a ciphertext copied into another row does not decrypt; **never returned
  by any route**. The list shows name, kind, base URL, owner, the scopes and expiry the forge reported,
  `encryptionState` (as the SSH keys and tokens show it, so a rotation of `ENCRYPTION_KEY` lists the row
  as *to rotate* — see [`KEY_ROTATION.md`](../../../en/KEY_ROTATION.md)), the last discovery and the
  number of targets imported through it.
- **Rotation replaces the token in place** (`PUT …/token`), re-probed, the row and its links kept.
  0022 rotates by delete-and-add because nothing points at a token but repositories; here the discovery
  snapshot and the provenance of imported targets hang on the row, and deleting it would orphan them for
  a routine gesture. An expiry the forge reported is shown, and announced fourteen days before.
- **Deleting a connection deletes its snapshot and its provenance links, and no target.** An imported
  repository is a target like any other from the moment it is created (§5).
- **Who: administrators**, as for SSH keys, HTTPS tokens and repositories. A connection reveals the
  name of every repository an organisation holds, and an import creates targets — both are an
  administrator's today. Integration API keys ([0024](0024-integration-api-keys-act-for-an-account.md))
  are not accepted on these routes in v1.
- **Audited** under a new operation, `FORGE_CONNECTION_CHANGED` (created, token replaced, renamed,
  deleted), rather than the `SETTING_UPDATED` the SSH keys and tokens use: a connection is a standing
  read access to a whole organisation, and an auditor looking for it should not have to read every
  settings change to find it.
- **Signalled to the SIEM** ([0025](0025-siem-events-leave-through-the-outbox.md)). The highest
  identifier in use is `VECTI-SEC-033` (reserved by 0035; `SecurityEventType` declares up to `032`).
  This decision reserves the next three — re-checked against `SecurityEventType` and the open ADRs when
  lot D1 starts, since another proposal may have taken them meanwhile:

| Id | Event | Severity | Why the SOC wants it |
|---|---|---|---|
| `VECTI-SEC-034` | Forge connection created, its token replaced, or deleted | 6 | a standing read access to an organisation's whole list of repositories appeared, changed hands or went |
| `VECTI-SEC-035` | Repositories imported from a forge | 5 | many targets — and the clone credentials attached to them — created in one gesture; once per import, with its count, never once per target |
| `VECTI-SEC-036` | Forge connection refused: blocked destination, write scope, or a credential presented to another host | 5 (`failure`) | a base URL aimed at the internal network or the metadata endpoint, or a token broader than declared, is how an SSRF or a credential-harvesting attempt shows itself |

**The connection's token does not clone.** Clone credentials stay what 0022 and the SSH keys made
them, chosen per host at import (§5). Four reasons, each sufficient:

- **The scopes differ.** On GitHub the discovery token can be *Metadata: read* only — it cannot read a
  line of code. A token that clones needs *Contents: read*. Using one for both widens the discovery
  token to read every repository of the organisation, for the convenience of not creating a second one.
- **The places differ.** The discovery token never leaves the control plane. A clone token travels,
  sealed, to every `delegated` agent that claims a scan of a repository using it. One credential for
  both would put the organisation-wide listing token on every agent.
- **The hosts differ.** GitHub's API answers at `api.github.com` and clones at `github.com`; 0022 binds
  a clone token to the host it is presented to, and a shared credential would need two bindings, which
  is the rule 0022 exists to prevent.
- **The lifecycles differ.** Rotating the discovery token should not break the night's scans.

*Rejected:* **reusing the connection's token as the clone credential** (above); **a GitHub App or
GitLab OAuth application** — the better credential in the long run (short-lived installation tokens,
approved by the organisation, not tied to a person), and a registration flow, a private key to keep and
a callback route to expose: a follow-up (§6), not v1; **storing the token in the settings table as the
ticketing token is** — one connection per installation, while an estate commonly spans a cloud
organisation and a self-hosted instance.

### 3. Discovery is a job, and its result a snapshot

**A discovery is a row, run in the background, polled by the screen.** `POST
/api/v1/forge-connections/{id}/discoveries` answers `202` with the run's id; the run is claimed from the
table by a control-plane instance under a lease, as scans are (0002), so a restart resumes it rather than
losing it. Its states are `pending`, `running`, `completed`, `partial` and `failed`, with counters the
screen shows while it runs: namespaces seen, repositories seen, requests made, time spent waiting on a
rate limit. One discovery runs per connection at a time; a second request answers `409` with the running
one's id.

*Rejected:* **synchronous discovery in the request.** A GitLab instance of three thousand projects is
thirty pages, plus a language call per project: minutes. A request held that long is cut by the first
proxy in front of the control plane, and a restart in the middle leaves no trace of what was seen.

**What is listed.** Namespaces first, then their repositories:

| Forge | Namespaces | Repositories |
|---|---|---|
| GitHub | the connection's owner — a fine-grained token is issued for exactly one | `GET /orgs/{owner}/repos?type=all&per_page=100` (or `GET /user/repos` for a user owner) |
| GitLab | `GET /groups?min_access_level=10&per_page=100` | `GET /projects?membership=true&pagination=keyset&order_by=id&sort=asc&per_page=100` |
| Bitbucket Cloud | `GET /2.0/user/permissions/workspaces` | `GET /2.0/repositories/{workspace}?pagelen=100` |
| Bitbucket Data Center | `GET /rest/api/latest/projects?limit=100` | `GET /rest/api/latest/projects/{key}/repos?limit=100`, then the default branch per repository |

**`membership=true` and `min_access_level` are not optional on gitlab.com**: without them the API lists
every public project and group of the service — millions — and a discovery would page through other
people's repositories until its cap. The adapter's tests assert the parameters, not just the result.

**What is kept per repository**: the forge's **stable id**, full path, namespace path, name, default
branch, archived, fork, visibility, last activity (GitHub `pushed_at`, GitLab `last_activity_at`,
Bitbucket `updated_on`), primary language, size, the HTTPS and SSH clone URLs and the web URL.
**Unknown is not zero** — the rule of [0007](0007-none-is-not-an-empty-list.md) applied to metadata:
GitLab gives the size only to a Reporter (`statistics=true`) and languages only through one call per
project; Bitbucket Cloud has no archived flag at all. A value the forge did not give is stored `null`
and shown *unknown*, and a filter on it says how many repositories it could not judge, rather than
treating them as small, language-less or active.

**Pages, limits, waits.**

- Pages follow the forge's own mechanism (GitHub's `Link`, GitLab's keyset `Link`, Bitbucket Cloud's
  `next`, Data Center's `nextPageStart`). **A next-page URL is followed only if its scheme, host and port
  are the connection's**; anything else fails the discovery with `VECTI-SEC-036`. The guard would check
  the new destination, but the token would already be on its way to it.
- **Rate limits are honoured, never raced**: `Retry-After`, `X-RateLimit-Reset` (GitHub) and
  `RateLimit-Reset` (GitLab) set the wait. A wait up to sixty seconds is spent inside the run; a longer
  one ends the run `partial`, its counters saying when the limit resets, and the next run starts again.
  A `5xx` or a timeout is retried three times with back-off, then fails the page.
- **Bounds**: ten seconds per request (`OutboundJson`'s), thirty minutes and twenty thousand repositories
  per run; past either the run ends `partial`. A larger estate is discovered per group, which the screen
  offers.
- **A `401` fails the run** — "token rejected or expired". **A `403` on one namespace** marks that
  namespace *not readable with this token* and the run continues: one group the token cannot read is not
  a reason to show nothing of the others, and it is not a reason to pretend it was empty either.

**The outbound guard, reused — not a second HTTP client.** Every call goes through `OutboundJson` and
`PinnedHttpSender`: the address checked is the address reached, redirects are refused, Vectispire's
reserved endpoints are refused under every policy. The policy is chosen per connection, as the ticketing
integration chooses it: **`PUBLIC_ONLY` for the cloud editions**, whose hosts are fixed and cannot be
typed, and for a typed base URL unless the administrator ticks *"this server is on the internal
network"*, which selects **`INTERNAL_ALLOWED`** — a GitHub Enterprise Server or a self-managed GitLab on
the internal network is the common case, not the exception, and link-local stays refused under it. The
base URL is validated when saved and **re-validated at every run**, since the name may resolve
elsewhere by then. The `Authorization` header is attached only to a request whose host is the
connection's — the rule 0022 applies to clone tokens, applied to this one. `OutboundJson` today returns
a body and no headers; lot D2 gives it a paged call that returns the headers the adapters need
(`Link`, `Retry-After`, the rate-limit headers, the scope headers), so that the door stays the only door.

**The snapshot.** A run writes into `t_forge_repository`: one row per repository the connection has ever
seen, keyed by connection and forge id, with its metadata, the run that first saw it and the run that last
saw it. Re-running a discovery is therefore a **comparison**:

- **new** — first seen by this run;
- **changed** — renamed or moved (same forge id, different path), default branch changed, archived;
- **gone** — seen before, absent from this run. **Only a `completed` run marks a repository gone**: a
  partial listing proves nothing about what it did not reach, and inferring a deletion from it would be
  0007's defect exactly.

A repository gone or archived on the forge **is not deleted from Vectispire**: its target, if imported,
is flagged on the discovery screen and keeps its history; removing it stays a person's gesture.

**Who sees a discovery: administrators**, as for the connection. A discovery lists repositories no
grant covers yet — a reader with a project grant would learn the names of the whole organisation.

### 4. Selection: what a person chooses, and how a repository is recognised

The discovery screen is a table of the snapshot with **filters** — archived (hidden by default), forks
(hidden by default), last activity older than N days, language, visibility, namespace, a pattern on the
full path (`acme/payments/*`), *already a target* (shown, greyed, not selectable) — and **select all
matching / none / invert**. The selection is a set of forge ids; what is imported is what was ticked,
never what a filter matches at import time.

**Recognising a repository already present.** A new rule beside `normalizeHost`, `RepositoryUrl.identity`
(brought by the repository form's duplicate refusal, answer 6, and reused here):
the host as `normalizeHost` writes it, then the path — without `.git`, without trailing slash, lower
case — and nothing of scheme, user or port, the scp form `git@host:group/repo.git` read as its path. A
discovered repository **is already present** when the identity of its HTTPS *or* its SSH clone URL
equals the identity of an existing target's URL, **whatever that target's sub-path**: a monorepo already
split into sub-path targets is shown *present (3 targets)*, not offered again. Once imported, the
**provenance link** (§5) recognises it by forge id, so a repository renamed on the forge is still the
same target.

- Lower-casing the path accepts that two repositories differing only by case on a case-sensitive server
  would be taken for one. None of the three forges allows that, and the cost of the opposite — a
  duplicate for every `Acme/API` typed as `acme/api` — is the defect this rule exists to prevent.
- A clone URL whose SSH host differs from the HTTPS host (`ssh.example.org`, port 443 variants) is
  matched through the forge's own two URLs, which is why both are kept in the snapshot.
- The import re-checks identity **inside its transaction** (§5); the preview's verdict is advice.

**Mapping into solutions and projects — proposed, shown, editable.** 0023 infers nothing; here the
proposal is shown and a person confirms it, which is the difference between inferring and suggesting:

| Forge | Solution proposed | Project proposed |
|---|---|---|
| GitLab | the top-level group | the repository's parent group below it (`acme/backend/payments/api` → project `backend/payments`); a repository directly under the top-level group → a project named after that group |
| GitHub | the organisation | one project per repository, named after it — GitHub has no level between them; editable like every proposal |
| Bitbucket Cloud | the workspace | the Bitbucket project |
| Bitbucket Data Center | one solution named after the connection | the Bitbucket project |
| any | personal namespaces: none — listed, **unticked** | none — the repository is imported into no project |

- An existing solution or project **of the same name** (as `SolutionAdministrationService` compares
  names) is **reused**, marked *existing*, never renamed or moved.
- Every proposal is editable per namespace and per repository: rename the proposed solution or project,
  choose an existing one, or *no project*.
- **The preview** (`POST …/imports/preview`, nothing written) states what the import would do: solutions
  and projects to create and to reuse, targets to create, repositories skipped and why (already present,
  empty repository, no default branch), the clone credential per host, the schedule, the first scans and
  their spread — and **who will see the new targets**: administrators, plus the holders of a grant on
  each reused project, named by count; a new project has no grant, and the preview says *visible to
  administrators only* until somebody makes one.

*Rejected:* **an automatic mapping applied without a preview** — 0023's rule against inferring holds for
anything a person has not seen; **flattening GitLab's nesting into nested solutions** — 0023 has two
levels on purpose, and a third would change every aggregate and every grant; **matching by URL string**
— `https://github.com/Acme/api` and `git@github.com:acme/api.git` are one repository.

### 5. Import: ordinary targets, a default schedule, staggered first scans

`POST /api/v1/forge-connections/{id}/imports` takes the selection, the edited mapping, the credential
per host, the first-scan option and an optional required agent label. **Up to 1,000 repositories per
import, in one transaction**: it creates everything or nothing, so a failure halfway leaves no half-filed
estate to clean up by hand. A larger selection is several imports.

- **Through the existing services.** Each target is created by `RepositoryAdministrationService` and
  each solution and project by `SolutionAdministrationService` — the same refusals as the forms (a
  credential in a URL, an HTTPS token on another host, a duplicate project name), the same audit lines.
  The import is a loop over gestures that already exist, not a second way to create a target.
- **The clone credential is chosen per host.** An SSH key → the forge's SSH URL; an HTTPS token (0022,
  bound to that host) → the HTTPS URL; none → the HTTPS URL, for public repositories. When exactly one
  HTTPS token is bound to the forge's clone host, it is proposed. A private repository imported with no
  credential is allowed and warned about in the preview: its first scan will fail with *requires
  authentication*, visibly.
- **Branch**: the default branch at discovery. A later change of default branch is shown as *changed* by
  the next discovery; the target is not altered behind its owner's back.
- **Schedule**: none of its own, so **the weekly default applies, spread by id** — three hundred imported
  targets do not all rescan on the same Monday morning. Lot D6 depends on that default having landed;
  without it an imported target would have no schedule at all, which is the state the default was made
  to end.
- **First scan: optional, off by default, staggered.** When asked, each new target is queued through
  `TargetScans.queue` with `not_before` = now + *k* × spacing (sixty seconds by default, editable in the
  import between ten seconds and ten minutes; three hundred repositories over five hours at the
  default). A target already waiting is skipped, as the scan button skips it.
- **Idempotent by construction.** A repository already linked to the connection, or already present by
  identity, is skipped and reported *already imported*; replaying the same request creates nothing.
- **Visibility.** The import creates **no grant**. New targets are visible to administrators and,
  through 0023, to whoever holds a grant on the project they are filed into. Granting stays on its own
  screen, audited as `TEAM_ACCESS_CHANGED` and signalled as `VECTI-SEC-011` — folded into a bulk import, a
  grant would be easy to miss in review.
- **Audit and SIEM.** Each target gets the entry the form writes (*Repository added: …*, redacted), with
  *imported from connection N, discovery M*; each solution and project created gets its usual entry; one
  `FORGE_IMPORT_APPLIED` entry summarises the import (counts, connection, discovery, actor); and
  `VECTI-SEC-035` is signalled **once per import** — a SOC wants one event for one gesture, not three
  hundred.
- **Provenance.** `t_forge_import_link` (repository id, connection id, forge id) records where a target
  came from. It lives in the new module, with **no foreign key** across modules: the module listens to
  `TargetDeleted` and deletes its link, as 0035's tables listen to `ProjectDeleted`. Deleting a target,
  editing it, moving it to another project — all exactly as for a target typed by hand.

*Rejected:* **queueing every first scan at once** — the agents would drain the queue in order anyway, but
the clones would hit the forge in one burst (abuse detection on github.com, a self-managed GitLab's
throttles), and the manual scans and CI gates behind them would wait for hours; **no first scan at all** —
the request is to see the estate, and a weekly default would show the first figures up to seven days
later; **mirroring the forge's membership into grants** — Vectispire's grants would then be decided by
whoever administers the forge, a token able to read members needs a broader scope, and a person removed
from a GitLab group would keep their Vectispire access until the next sync, or lose it without anybody
in Vectispire deciding so; **an import job like the discovery** — creating a thousand rows is seconds,
and a transaction is the simplest way to promise all or nothing.

### 6. Where it sits, and what is out of scope

**A new vertical module, `core/forges/`** (`web`, `internal`, `persistence`), whose `package-info`
declares `targets` (target, solution and project creation, `TargetScans`, `TargetDeleted`) and
`access::security` (its routes' markers), each with its reason. `targets` does not depend on it: the
dependency runs one way, and a target never knows it was imported. `ArchitectureTest.MODULES` and
`ModularityTest.MODULES` gain it.

**Out of scope for v1, and the follow-ups in the order proposed:**

1. **Scheduled re-discovery with a notification** of new repositories — the manual re-run and its
   comparison come first; a schedule is a cron on the same job.
2. **Webhooks or system hooks for automatic onboarding** of a repository created on the forge — an
   inbound route per forge, its secret, and a decision about whether a repository becomes a target
   without a person.
3. **Continuous synchronisation** (renames, archival and deletion applied to targets).
4. **GitHub App and GitLab OAuth application** credentials (§2).
5. **Container registry discovery** — GHCR, the GitLab registry, Docker Hub, Harbor — for image targets.
6. **Other forges**: Azure DevOps, Gitea and Forgejo.
7. **Discovery through an agent**, for a forge the control plane cannot reach: the connection's token
   would have to be sealed to one designated agent, as 0035 plans for its exports.
8. **Grants at import** (a team named on the projects created) — refused for v1 (decided 2026-10-03,
   answer 5); reopened only by a decision of its own.
9. **Integration API keys** on the discovery and import routes, for scripted onboarding.

## Alternatives considered

Each section records its own rejections; the larger ones, together:

- **A CSV or YAML upload of repositories** instead of a forge API. No credential to keep and no
  outbound call; and the administrator still has to know the list, which is the problem. Kept as a
  possible later import format, not as the answer.
- **The token clones too** (§2): one credential instead of two, widened to read every repository's
  code, carried to every agent, bound to two hosts.
- **Synchronous discovery** (§3): fine on twenty repositories, cut by the first proxy on three thousand.
- **GraphQL** (§1): fewer requests, a cost model that is harder to bound, version skew on self-hosted
  editions, and nothing for Bitbucket.
- **Automatic mapping without a preview, or mirroring forge permissions** (§4, §5): both make the forge
  the authority over what Vectispire shows and to whom.
- **A separate "discovered repository" kind of target**, scanned without being imported: a second
  target model for every query, every grant and every score to know about.

## Consequences

- A new module, `forges`, with four tables — `t_forge_connection`, `t_forge_discovery`,
  `t_forge_repository`, `t_forge_import_link` — written once under `db/migration/common` with the type
  placeholders, from the next free version when lot D1 lands; no foreign key leaves the module, so no
  vendor directory is needed (0027). `integrationTestAll` runs on the lot, as for every migration.
- One more encrypted store, which `ENCRYPTION_KEY`'s rotation procedure has to list beside the SSH keys
  and tokens.
- A new identity rule for repositories, `RepositoryUrl.identity`. **The repository form refuses a
  duplicate by the same rule too** (decided 2026-10-03, answer 6), as a separate change built on its own
  branch: the rule lands there, and the lots here reuse it rather than write a second one.
- `OutboundJson` gains a paged call that returns headers; every adapter goes through it.
- Two audit operations (`FORGE_CONNECTION_CHANGED`, `FORGE_IMPORT_APPLIED`), three SIEM identifiers and a
  catalogue entry for each, in both languages.
- New routes and their OpenAPI contract; the front end gains a connections screen, a discovery screen
  with its progress, a selection table and a preview.
- **The connection's token is a new standing access** to the list of an organisation's repositories,
  held by the control plane. It is read-only where the forge allows it and stated as such where it does
  not; that residual — a GHES classic `repo` token, GitLab's `read_api` that can also read files through
  the API — is written in the administration guide, not hidden.
- A forge the control plane cannot reach (an internal GitLab reachable only from an agent's network)
  cannot be discovered in v1.

## Decided on 2026-10-03

The product owner settled the eight questions the proposal left open, each as recommended:

1. **Bitbucket in the lot after** (D8); v1 is GitHub and GitLab. If the first estates turn out to be on
   Bitbucket, D8 moves before D4.
2. **Classic GitHub tokens on a GHES without fine-grained tokens are accepted, flagged as able to
   write** — in the list, the audit entry and `VECTI-SEC-034`'s details. Refusing them would exclude
   those servers entirely.
3. **GitHub: one project per repository**, named after it, editable like every proposal.
4. **The first scan at import is off by default**; when asked, the scans are spaced **sixty seconds**
   apart by default, editable between **ten seconds and ten minutes**.
5. **No team grants at import in v1.** A grant stays a separate, audited gesture with its own SIEM event.
6. **The manual repository form refuses a duplicate by the identity rule too**, as a separate change
   built in parallel. `RepositoryUrl.identity` lands with it; these lots reuse it.
7. **Personal namespaces are offered, unticked.**
8. **The bounds stand**: 1,000 repositories per import, 20,000 per discovery, thirty minutes per
   discovery.

## Implementation, in lots

| Lot | Content | Size |
|---|---|---|
| D1 | The `forges` module: `t_forge_connection`, encryption with the row as context, the probe and scope allow-list per forge, routes (administrators), `FORGE_CONNECTION_CHANGED`, `VECTI-SEC-034` and `036`, `encryptionState`; `integrationTestAll` | M |
| D2 | `OutboundJson`'s paged call with headers; same-origin next pages; `Retry-After` and rate-limit waits; the token attached to its host only | S |
| D3 | The discovery job (`t_forge_discovery`, claim and lease, progress, `partial`), the snapshot and its comparison; the GitLab adapter, with recorded-response tests asserting `membership=true` and `min_access_level` | L |
| D4 | The GitHub adapter (cloud, data residency, GHES), recorded-response tests | M |
| D5 | The selection routes (reusing `RepositoryUrl.identity`, which the repository form's duplicate refusal brings), filters, mapping proposal, preview | M |
| D6 | The import through the existing services, credentials per host, staggered first scans on `not_before`, provenance links and their `TargetDeleted` listener, `FORGE_IMPORT_APPLIED`, `VECTI-SEC-035` — after the weekly default has landed | M |
| D7 | The interface: connections, discovery with progress and comparison, selection table, mapping editor, preview, import result | L |
| D8 | The Bitbucket Cloud and Data Center adapters | M |
| D9 | Documentation in English and French: administration (connections, scopes per forge, the residuals), user guide (discovery and import), SIEM catalogue, API reference, key rotation | S |

D1 to D3 and D5 to D7 make the feature for GitLab; D4 adds GitHub without touching them. D1 is useful
alone only as a probe, so it ships with D3.
