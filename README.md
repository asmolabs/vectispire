# Veriscape

Veriscape is a software dependency and security tracking application built around SBOM (Software Bill of Materials) analysis. It scans Git repositories and container images, detects known vulnerabilities, hardcoded secrets, problematic licenses, and infrastructure-as-code misconfigurations, then centralizes the results in a single dashboard — in the spirit of a unified ASPM (Application Security Posture Management) platform. Scanning runs in local Docker containers.

Built with [Spring Boot](https://spring.io/projects/spring-boot) on JDK 25 and [Angular](https://angular.dev) over PostgreSQL.

## Features

- **SCA analysis (dependencies)**: SBOM generation (Syft) and known-vulnerability detection (Grype), with severity, CVE, and affected component.
- **EPSS / CISA KEV enrichment**: every vulnerability is enriched with its exploitation probability (EPSS) and "actively exploited" status (KEV catalog), to prioritize beyond the raw CVSS score.
- **Direct versus transitive dependencies**: each issue records whether the project declared the package itself or something else pulled it in, read from the SBOM's dependency graph. A critical CVE in a declared dependency is a version bump this afternoon; the same CVE four levels down waits on an upstream release. Ranked identically they produce a backlog nobody finishes, so the listing can be narrowed to what is fixable today. Unknown when the SBOM carries no dependency graph — a missing answer rather than a default one.
- **Secret detection** (gitleaks): finds hardcoded API keys, tokens, and credentials in scanned repositories.
- **License compliance**: evaluates a configurable license blocklist against data already present in the SBOM.
- **End-of-life detection** (endoflife.date): flags platforms and runtimes whose security support has ended — the container's own distribution first of all. A whole class of risk with no CVE attached: nothing will be fixed for the *next* vulnerability, whatever it turns out to be. Coverage is deliberately scoped to products (languages, runtimes, frameworks, distributions), not every library.
- **IaC scanning** (checkov): detects Terraform/Kubernetes misconfigurations in repositories.
- **Security and Quality sections.** The navigation is grouped: *Sécurité* holds an
  overview that finally shows the gate verdict per target — computed since gate policies
  existed and displayed nowhere until now — alongside the issue backlog, repositories and
  containers. *Qualité* ranks the code-quality backlog by rule, file and repository, and
  says plainly that none of it can fail a build. The overview also names the two states
  no other screen did: a target never scanned, and one whose last scan failed — both have
  an empty backlog, and an empty backlog passes every policy.
- **Source-code analysis** (Semgrep, off by default): reads the code itself — a
  concatenated SQL query, a command handed to a shell, an unverified TLS certificate —
  which no other scanner here sees. Produces two kinds of finding: *security* ones, gated
  like any vulnerability, and *quality* ones, which are visible in the backlog and can
  never fail a CI gate. Runs with the network disabled. **Zanshin bundles a single rule**
  — the public rule sets are not redistributable, which is a licensing constraint rather
  than an oversight — so real coverage comes from a rule set you install yourself; see
  [Installing a Semgrep rule set](#installing-a-semgrep-rule-set).
- **Issue tracking and triage**: every finding is tracked across scans as an *issue* — first seen, times seen, whether a fix exists, and a triage decision in VEX vocabulary (affected / not affected / fixed / under review) with a justification, and optionally a **review date**. A suppression is a statement about a context — "not reachable in our configuration", "not shipped in production" — and contexts change; at its review date the issue returns to *under review* with its justification and comment intact. Each scan reports what it *changed*: new issues, resolved issues.
- **Backlog over time**: the dashboard's figures are snapshots, which answer "how much" and never "better or worse than last month". A series does: the standing backlog day by day, what appeared against what was resolved, and the mean time to resolve — absent rather than zero when nothing was resolved, because zero reads as "fixed the day it appears". Narrowed by the reader's visibility like every other view, and computed in a pure function rather than in SQL, because four engines spell date truncation four ways.
- **Weekly posture report** (off by default): every other notification fires when something *appears*, which is right for an alert and wrong for a report — on a quiet week nobody is told anything, and a quiet week is also the week a target has silently not been scanned for twenty days. Once a week to the webhook and the e-mail recipients: how much there is, which way it is moving, and what was never examined. It needs no outbox, unlike a scan delta: a report is derived from the database, so a failed send is simply recomputed on the next tick.
- **Bulk triage**: one CVE across forty repositories is one judgement about one context, not forty — and deciding it forty times is how a backlog stops being triaged at all. Narrow the list, select, decide once. All or nothing in one transaction, with each issue still recording its own transition in the triage history, because a bulk decision that changed forty rows silently would be indistinguishable from forty rows edited by hand.
- **Periodic rescanning**: each target carries a scan interval *or* a cron expression, honoured by a built-in scheduler — the point being that new vulnerabilities appear in code that hasn't changed. The expression wins when both are set: an interval drifts a few minutes each run, so a scan configured for the quiet hours eventually runs in the middle of the day.
- **HTTP API and CI policy gate**: trigger scans, read issues, and ask "should this build fail?". The verdict names the policy it applied, and a `policy` object in the request can only *tighten* what applies, never loosen it — the rules used to arrive in the request body, which meant each project decided its own bar. The policy applied is a **stored, versioned** one — global, or overridden per target — written on *Administration → Gate policies*; where none is stored, the built-in default applies, and the screen shows it beside what is stored so that "not set" and "set to the same thing" do not look alike. Authenticated with the API keys the UI issues, and callable without writing the request by hand: [`ci/zanshin-gate.sh`](ci/zanshin-gate.sh), a GitHub composite action and a GitLab template.
- **Tracker tickets** (GitLab, Jira): opens one ticket per problem that would fail a build, using the same policy — one threshold, defined once. The reference is kept on the issue, so a tracker outage is retried and never duplicated.
- **Notifications**: a webhook, a **Microsoft Teams** card and an **e-mail** fire when a scan makes something appear or reappear — not on every scan, which is what keeps the channel readable. The three are independent rather than exclusive: a team wants the card in its channel *and* the mail on a distribution list. Each destination gets its own outbox row, so a mail server being down does not make Teams receive the message twice on the retry. Teams is reached through a Power Automate **workflow** — the Office 365 connector it replaces was retired — and Zanshin posts an Adaptive Card, so nothing has to be mapped in the designer. The message is written to an **outbox in the same transaction as the scan's results** and delivered by the scheduler with capped exponential backoff, so a crash between the commit and the POST no longer loses it silently and a briefly unreachable endpoint is retried instead of logged once. Webhook messages can be **signed** (HMAC-SHA256 over the timestamp and the exact body, in `X-Zanshin-Signature`) so a receiver can tell a message Zanshin sent from one sent by whoever learned the URL — worth it for a script, a bus or your own gateway, which can check it; Slack and Teams accept whatever arrives. Empty secret means unsigned, which is what an existing deployment stays.
- **Exports**: **SARIF 2.1.0** for GitHub code scanning / GitLab / Azure DevOps — which is what gets a finding out of the dashboard and onto the pull request that introduced it — plus an OpenVEX document built from the triage decisions, issues as CSV, the SBOM as the cataloguer produced it, and two documents written for a person rather than a tool: a target's **posture** and its **detection-and-triage history**, both as PDF.
- **Detection and triage history**: per repository, every scan with the project version it read, the issues that scan observed, and every triage decision taken on them — from which status to which, by whom, with which justification, and against which version. For the reader who has to be convinced after the fact and was not there. Exportable as PDF and CSV. An issue nobody triaged is printed saying so: silence would let it pass for a decision that was merely not written down.
- **User management** and **audit log**: roles (SUPERUSER/ADMIN/USER), guardrails (can't delete your own account or the last active superuser), traceability of sensitive actions.
- **Optional single sign-on** (OpenID Connect, tested against Keycloak): the provider answers *who is this*, and Zanshin still issues its own session — so the visibility rules, the audit trail, the session lifetimes and the API keys keep working unchanged. **No account is created on sign-on**: an administrator creates it first, and the role stays Zanshin's to decide. Whoever can obtain a token from a shared realm must not thereby obtain a reader's view of every target. The first sign-on binds the account whose username matches the claim, and every later one matches on the provider's subject — a username is not stable for the life of a person.
- **Scanning that stays on the machine**: every scanner runs in an ephemeral container with the network disabled and a read-only mount. **There is one scan backend, and it is Docker.** An OSV.dev matcher and an HTTP sidecar were considered and dropped: the sidecar was redundant, and OSV matching bought little that a pinned Grype image does not ([decision 0010](docs/architecture/decisions/0010-one-scan-runner.md)).

## Architecture

The pipeline is split in two along one line: **`ScanRunner` runs the scanners and never
touches the database; `ScanIngestor` reads its results and never runs a container.** That
split is what lets the same code execute inside the control plane or on a remote agent
that has no database credentials.

| Step | Tool | Image pinned by digest |
|---|---|---|
| SBOM | Syft | yes |
| Vulnerability matching | Grype | yes |
| Secrets | gitleaks | yes |
| IaC | checkov | yes |
| Source code (off by default) | Semgrep | yes |

Every scanner runs in an ephemeral container with **the network disabled**, a read-only
mount, `cap_drop: ALL` and `no-new-privileges`. Nothing about the scanned code leaves the
machine. The only outbound calls a scan makes are the EPSS and CISA KEV lookups, which
carry CVE identifiers and nothing else — and the end-of-life catalogue, which carries
product names and versions.

Results are normalized into a single `Finding` table (type, severity, identifier, package, source, EPSS/CVSS scores, KEV status, fix version), in addition to the raw JSON blobs (`Scan.sbom`, `Scan.cves`) kept for audit purposes.

A `Finding` is an *observation*, valid for one scan. Above it, an `Issue` tracks the same problem across scans — identified by a fingerprint that deliberately ignores the package version, so a dependency that stays vulnerable through three patch releases keeps one history and one triage decision. Two axes are kept strictly separate: `state` (open/resolved) is written only by the pipeline, from what the scanners observe; `triage_status` (VEX) is written only by a human. Conflating them would make "resolved" meaningless — a suppressed finding and a genuinely fixed one must not look alike. See [`IssueSyncService`](zanshin-java/zanshin-core/src/main/java/com/asmolabs/zanshin/core/services/IssueSyncService.java).

The architecture dossier — overview, data model, security, deployment, and a decision register with the discarded alternatives — is in [`docs/architecture/`](docs/architecture/) (written in French). For diagrams of the layered architecture, the full database schema, and the scan pipeline's sequence flow, see [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

### Distributed scanning: agents

A scan is executed by an **agent**. There are two kinds, and both are rows in the same
table, listed together on the `/agents` page:

- the **built-in agent** — this very web process. Created automatically at startup, no
  configuration, which is why a single-machine install works out of the box;
- **remote agents** — separate worker processes on other machines, speaking the four-route
  agent protocol (`hello`, `jobs`, `heartbeat`, `result`).

Both run the same code (`ScanRunner`), and both send back the scanners' raw output for
the control plane to normalize (`ScanIngestor`). A result produced on another machine is
therefore indistinguishable from a local one: same `Finding` rows, same EPSS/KEV
enrichment, same licence policy, same issue reconciliation.

Reasons to add a remote agent: keep the Docker socket off the host that serves the UI, reach
a repository or registry that is only routable from another network segment, or add
capacity. **Disabling the built-in agent** is how you say "run nothing here" — queued
scans then wait for a remote agent instead of quietly using the web instance.

A remote agent polls over HTTP with an API key carrying the `agent` scope, so it needs no
inbound port and **no database access**. That last point is a security property, not a
detail: an agent with a database connection would also need `ENCRYPTION_KEY`, i.e. the
ability to decrypt every deploy key Zanshin holds.

| Credentials mode | What the controller sends | When to use it |
|---|---|---|
| `local` (default) | nothing | the agent's own machine has git access. A compromised agent yields only what that machine was granted |
| `delegated` | the deploy key, per job | a trusted machine. Requires HTTPS (refused otherwise), the key is never written to disk beyond a `0600` temp file, and every delivery is audited |

```bash
# On the agent's machine — the key comes from /agents, shown once
ZANSHIN_URL=https://zanshin.internal \
ZANSHIN_AGENT_TOKEN=zsk_... \
node dist/agent/main.js
```

Or as a container, which is how it is meant to be deployed:

```bash
docker build -f Dockerfile.agent -t zanshin-agent .
docker run --rm -e ZANSHIN_URL=... -e ZANSHIN_AGENT_TOKEN=zsk_... \
  -v /var/run/docker.sock:/var/run/docker.sock zanshin-agent
```

The agent runs **the same `ScanRunner`** as the built-in worker, which is what makes a
result produced elsewhere indistinguishable from a local one. A layering test enforces
what it may import: `scanning/` and `domain/`, never `persistence/` — an agent with a
database connection would also need `ENCRYPTION_KEY`, i.e. the ability to decrypt every
deploy key Zanshin holds.

**Container image scans are distributed too**, and they carry no key at all: an image is
pulled from a registry, not cloned from git, so registry credentials belong to the Docker
configuration of whichever machine scans. Secrets, IaC and source-code analysis do not
apply to an image and stay `null` — declaring them scanned would silently resolve their
whole history for that target.

See [`docs/architecture/04-runtime-and-deployment.md`](docs/architecture/04-runtime-and-deployment.md)
for the decisions and the known limits.

**Running more than one web instance.** Most of what made that unsafe is now fixed: the
scan claim is transactional (`FOR UPDATE SKIP LOCKED`), the periodic work has exactly
one owner across the fleet, startup recovery no longer fails another worker's scans, and
the login throttle is counted in the database rather than in process memory. What it requires:

- **PostgreSQL or MySQL** (`ZANSHIN_DB_URL`; the engine is read from the URL). Both keep a
  claimed scan from reaching two workers;
- **nothing to run for the schema.** Flyway applies the migrations at startup, and the
  leader lease is what stops two instances migrating at once;
- nothing else. Sessions live in the database, not in process memory, so a client that
  lands on the other instance stays signed in. No cache, no shared state service.

The scheduler elects a single owner across the fleet, while every instance keeps claiming
work for its own built-in worker: a fleet whose instances only worked while holding the
lease would idle behind whichever one holds it.

Start it wrong and the application says so: it refuses, or warns, with the reason named.

## Quick start

Prerequisites: Node ≥ 24, Docker (for the scanners and, in development, for the database).

```bash
npm install
cd zanshin-java && ./gradlew :zanshin-core:bootRun   # API on http://localhost:8000
npm --workspace @zanshin/frontend start            # UI on http://localhost:4200
```

The schema is owned by **Flyway migrations** (`src/main/resources/db/migration/{vendor}/`) — `ddl-auto` is `validate`, deliberately: a
schema synthesised from the entities is not the one production will receive, and testing
against it would let a faulty script through. `SchemaParityIntegrationTest` asks Hibernate
to validate the entities against the schema Flyway really built, on all four engines.

```bash
# Flyway applies migrations at startup — there is no separate command to run.
# A new change is a new migration script in zanshin-core/src/main/resources/db/migration/<dialect>/.
```

### Main pages

| Route | Description |
|---|---|
| `/dashboard` | Overview |
| `/repositories` | Tracked Git repositories, scan history, finding details |
| `/security` | The gate verdict for every target, and the policy that produced it |
| `/quality` | Code-quality findings, aggregated by rule, file and repository |
| `/issues` | Issue backlog across scans, with triage (VEX) |
| `/containers` | Tracked container images |
| `/ssh-keys` | Encrypted SSH keys for cloning private repositories |
| `/api-keys` | Programmatic API keys (Argon2id hash, secret shown once) |
| `/agents` | Scan agents (built-in and remote), the queue, and leases (admin only) |
| `/settings` | Scan backend selection, enrichment toggle, license blocklist |
| `/users` | User management (admin only) |
| `/audit-log` | Audit log of sensitive actions (admin only) |
| `/history` | Per repository: every scan with its version, the issues it observed, and every triage decision — with PDF and CSV export |

## API and CI integration

The API is served from the same process and port as the UI, under `/api/v1`, and authenticates with a key created on the **API keys** page:

```bash
export ZANSHIN=http://localhost:8000
export ZANSHIN_KEY=zsk_...

# What can I scan?
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/repositories
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/containers

# Scan, then poll. A scan is queued on its target, not posted to a queue:
# the target is what carries the branch, the sub-path and the deployment key.
curl -X POST -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/repositories/1/scan
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/scans/42

# Should this build fail? The tightening fields are **flat**, not nested under "policy":
# an object the request record does not declare is ignored by the mapper, silently, and a
# pipeline that sent one would run on the stored policy while believing it had raised the bar.
curl -X POST -H "Authorization: Bearer $ZANSHIN_KEY" -H 'Content-Type: application/json' \
     -d '{"repository_id": 1, "fail_on_severity": "high", "fail_on_kev": true}' \
     $ZANSHIN/api/v1/gate
```

Or, without writing the call yourself — [`ci/zanshin-gate.sh`](ci/zanshin-gate.sh), with a
composite action in [`ci/github-action/`](ci/github-action/action.yml) and a GitLab template in
[`ci/gitlab/`](ci/gitlab/zanshin-gate.gitlab-ci.yml):

```yaml
- uses: ./ci/github-action
  with:
    url: https://zanshin.example.com
    token: ${{ secrets.ZANSHIN_TOKEN }}
    repository-id: 12
```

It exits **0** when the gate passes, **1** when it fails, and **2** when it could not be asked at
all — three codes rather than two, because a pipeline that reads "Zanshin was unreachable" as
"your code is clean" has no gate on the day the control plane is down. `--on-error warn` is the
other choice, and it says out loud that the build went through ungated.

The gate returns HTTP 200 with `{"passed": false, "violations": [...]}` when the policy is violated — a violated policy is an answer, not a transport error, and pipelines treat the two differently. Issues already triaged as *not affected* or *fixed* don't fail a build unless you ask for `include_triaged`.

The policy the gate applies is **the one an administrator stored**, and the verdict says which:
`policy.source` is `target`, `global` or the built-in default, with the `version` that was
applied. Policies are written on **Administration → Gate policies** (`PUT
/api/v1/gate/policies/global`, `PUT /api/v1/gate/policies/{kind}/{id}`), scoped globally or per
target, versioned rather than edited — a build that failed in March failed under a row that is
still there — and every change is audited as `GATE_POLICY_UPDATED`.

A target with no policy of its own follows the global one, and keeps following it when it
changes; an override replaces it **entirely** rather than merging with it. Removing an override
is a `DELETE` on the same path, and it restores inheritance rather than relaxing anything.

`fail_on_severity: "none"` switches the severity rule off — block on actively exploited findings
alone. It is not the same as a low threshold and not the same as the severity `unknown`, which
ranks below everything and would fail every build.

The tightening fields in the request body can only make the rules **stricter**. Every field's strict direction is defined per field, since it does not mean "greater": a *lower* severity threshold is stricter; `fail_on_kev` and `include_triaged` are stricter when `true`; `fixable_only` is stricter when **`false`**, because `true` excludes issues with no published fix — which is exactly the case that needs a human decision, not a green build. Anything refused comes back in `policy.ignored_relaxations`, alongside the `source` and `version` actually applied.

Exports, all authenticated like every other route:

| Route | Document |
|---|---|
| `GET /api/v1/targets/{repository\|container}/{id}/issues.sarif` | SARIF 2.1.0 |
| `.../vex` | OpenVEX, built from the triage decisions |
| `.../issues.csv` | The backlog as rows |
| `.../posture.pdf` | The verdict and the backlog, for a person |
| `GET /api/v1/scans/{id}/sbom` | The Syft SBOM, served verbatim — 404 when the scan produced none |
| `GET /api/v1/history/repositories/{id}/export.pdf` | Detection and triage history |
| `.../export.csv` | The same, one row per decision |

SARIF is the one that puts a finding in front of the developer who introduced it, annotated on the line, in the pull request:

```bash
curl -H "Authorization: Bearer $ZANSHIN_KEY" \
     -o zanshin.sarif "$ZANSHIN/api/v1/targets/repository/1/issues.sarif"
gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
     -f commit_sha="$GITHUB_SHA" -f ref="$GITHUB_REF" -f sarif="$(gzip -c zanshin.sarif | base64 -w0)"
```

Triaged issues are uploaded as SARIF *suppressions* rather than dropped: removing them would make the platform re-report them as new on the next upload, undoing the triage work, and the suppression carries the justification. Zanshin's own issue fingerprint travels as a `partialFingerprint`, so a platform still matches an issue after the file moves or the line shifts. There is no generated API reference yet: the routes are the ones listed here and in the controllers under [`api/`](zanshin-java/zanshin-core/src/main/java/com/asmolabs/zanshin/core/api/). If one is added it will require a key like every other route — an anonymous map of the routes and payload shapes is a free reconnaissance step.

A key can be narrowed when it is created, and a CI key normally should be:

| Restriction | Effect |
|---|---|
| Scopes `read` / `scan` / `export` | What the key may do. A key that only publishes results needs `read`; one that queues scans needs `scan`. Missing scope → 403. |
| Target `repository:{id}` or `container:{id}` | What the key may reach — including the `/issues` listing and the exports, which are narrowed to that target. Another target → 403 (not 404: the caller already knows the id it asked for). |
| Expiry in days | After it, the key is refused as invalid. The row stays, so the listing still shows that the key existed. |

`GET /api/v1/issues` accepts `only_direct=true` to return just the packages the project declared itself — the subset a version bump fixes today, without waiting on an upstream release. Issues whose directness is unknown are excluded: a missing answer is not a positive one.

Defaults stay wide (every scope, every target, no expiry) because that is what a key granted before these existed, and because a form whose defaults break the pipeline teaches people to tick every box.

## Configuration

Runtime settings (enrichment, end-of-life, retention, notifications, licences, tracker, model review) are managed from the **Settings** page and stored in the `t_setting` table rather than as environment variables. A setting appears there only once a service actually reads it: a form that accepts a value and does nothing with it is worse than one that does not offer it.

Three things are *not* runtime settings, because they have to exist before the application can be used safely:

| Variable | Required | Purpose |
|---|---|---|
| `ENCRYPTION_KEY` | To store SSH keys | 32-byte key used to encrypt SSH private keys and tokens (AES-GCM). Without it, saving a secret is refused rather than written under something that cannot protect it. The application no longer carries a default key: it used to ship one in its own source, which meant a copy of the database file was enough to read every stored private key. **Prefer `ENCRYPTION_KEY_FILE` below.** |
| `ENCRYPTION_KEY_FILE` | Instead of `ENCRYPTION_KEY` | A path to a file holding the key — what a Docker or Kubernetes secret actually mounts. This is the recommended form: a variable is readable through `/proc/<pid>/environ`, `docker inspect`, an orchestrator's logs and a swept-up `.env`, and this is the one value whose exposure is the whole loss rather than a degradation. A trailing newline is not part of the key. **Setting this and `ENCRYPTION_KEY` together is refused at startup**, because nothing could then say which key is in force without picking one you did not. And a path that does not resolve — missing, unreadable, or an empty mount — **stops the application** instead of falling back: a deployment with no key still serves every screen, so a failed secret mount would otherwise be indistinguishable from a fresh install. |
| `ZANSHIN_MAIL_HOST` | To send alerts by e-mail | The SMTP relay, with `ZANSHIN_MAIL_PORT` (587), `ZANSHIN_MAIL_USERNAME`, `ZANSHIN_MAIL_PASSWORD`, `ZANSHIN_MAIL_FROM` and `ZANSHIN_MAIL_STARTTLS` (true). **Where to send is deployment configuration; who receives is a setting** — the relay holds a password and is the same for every message, the recipients change with the team. With no host there is no sender and no channel: an unconfigured destination is queued nothing rather than queued and failed. |
| `ZANSHIN_OIDC_ISSUER` | To offer single sign-on | The realm's issuer URL, e.g. `https://keycloak.example.com/realms/zanshin`. Zanshin discovers the endpoints from its `/.well-known/openid-configuration` rather than asking an operator to copy four of them correctly. **Setting it is the whole switch**: with no issuer there is no filter chain, no route and no button. Password login stays in either case — it is the way in when the realm is unreachable, and without it a broken issuer locks everybody out. Accompanied by `ZANSHIN_OIDC_CLIENT_ID`, optionally `ZANSHIN_OIDC_CLIENT_SECRET` (omit it for a public client) and `ZANSHIN_OIDC_NAME` for the button's label. |
| `ZANSHIN_SEMGREP_RULES_DIR` | To widen Semgrep's coverage | A directory of extra Semgrep rules, merged with the ones Zanshin ships. **Zanshin bundles a single rule**, so in practice this is where your coverage comes from — see [Installing a Semgrep rule set](#installing-a-semgrep-rule-set). If the directory is set and cannot be read, the SAST step fails rather than quietly scanning with the bundled rule alone. |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | To rotate `ENCRYPTION_KEY` | Comma-separated older keys, tried for **decryption only**. Values move to the current key as they are re-saved, and the SSH keys page marks the rows that still depend on an older one — so the variable can be dropped once none remain. Also how a value encrypted with the old published default key is read one last time; see [`docs/ROTATION_AND_PURGE.md`](docs/ROTATION_AND_PURGE.md). |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS_FILE` | Instead of the above | A file holding them, comma- or newline-separated. It exists for the same reason as `ENCRYPTION_KEY_FILE` and not for symmetry: an old key still decrypts live rows, and a rotation is the moment two keys exist at once — so without it, moving the current key to a file would mean putting the previous one back into the environment to finish the job. Same refusals. |
| `ZANSHIN_BOOTSTRAP_USERNAME` | First run only | Username of the initial SUPERUSER, created at startup when the `user` table is empty. |
| `ZANSHIN_BOOTSTRAP_PASSWORD` | First run only | Its password (8 characters minimum). |

Operational tuning (all optional, shown with their defaults):

| Variable | Default | Purpose |
|---|---|---|
| `ZANSHIN_DB_URL` | `jdbc:postgresql://localhost:5432/zanshin` | JDBC connection URL. The engine is read from the URL itself — there is no separate dialect variable to keep in step with it. |
| `ZANSHIN_DB_USER` / `ZANSHIN_DB_PASSWORD` | `zanshin` / — | Database credentials. |
| `ZANSHIN_PORT` | `8000` | HTTP port. The API and the agent protocol share it. |
| `ZANSHIN_PUBLIC_URL` | — | Public base URL, used in exports and tracker tickets so a link written today still resolves tomorrow. |
| `ZANSHIN_HOST_SSH` | `true` | A repository with no deployment key attached falls back to the scanning host's own `~/.ssh` — identities, `config`, agent and `known_hosts`, used whole. `false` on any installation where the people adding targets are not the people who own that key: the fallback is host-wide, so adding a URL is then enough to have Zanshin clone it with an identity nobody attached to it. |
| `ZANSHIN_EMBEDDED_WORKER` | `true` | `false` for a control plane that runs no scan itself. Queued scans then wait for a remote agent instead of quietly using the web instance. |
| `ZANSHIN_SCAN_MAX_CONCURRENT` | `2` | Concurrent scans for this instance's built-in worker. |
| `ZANSHIN_WORKER_LABELS` / `ZANSHIN_WORKER_INTERVAL` | — / `15s` | Labels this worker answers to, and how often it looks for work. Empty labels on purpose: the built-in worker takes only work with no requirement, or targeting would be useless on a single-instance install. |
| `ZANSHIN_QUEUE_LEASE` / `ZANSHIN_QUEUE_MAX_ATTEMPTS` / `ZANSHIN_QUEUE_CLAIM_ATTEMPTS` | `20m` / `3` / `12` | Lease held on a claimed scan, retries before it is abandoned, and retries of the claim itself under contention. |
| `ZANSHIN_SCHEDULER_INTERVAL` / `ZANSHIN_RELAY_INTERVAL` / `ZANSHIN_MAINTENANCE_INTERVAL` | `60s` / `60s` / `1h` | How often due targets are looked for, the notification outbox is drained, and housekeeping runs. |
| `ZANSHIN_LEADER_LEASE` | `180s` | How long the scheduler lease is held without renewal. Comfortably longer than one tick, so a slow tick does not hand the job to somebody else; short enough that a dead leader is replaced in about two minutes. |
| `ZANSHIN_IMAGE_SCAN_PLATFORM` | — | Platform to pull for a container scan, e.g. `linux/amd64` — the image scanned should be the one that runs in production, not the one that matches the scanner's host. |
| `ZANSHIN_SESSION_LIFETIME` / `ZANSHIN_SESSION_IDLE` | `12h` / `60m` | Absolute and idle session lifetimes. The absolute one bounds a stolen token's usefulness and no activity extends it; the idle one protects an unlocked screen. |
| `ZANSHIN_VEX_AUTHOR` / `ZANSHIN_VERSION` | `Zanshin` / `1.0.0` | Author and tool version recorded in exported documents — a VEX is an assertion about who said what, and when. |

**The scanner images are not configurable, and that is deliberate.** The five digests are
constants in [`ScannerImages`](zanshin-java/zanshin-common/src/main/java/com/asmolabs/zanshin/common/scanning/scanners/ScannerImages.java):
they execute on the scanning host and read input nobody controls, so they *are* Zanshin's
supply chain — whoever controls `anchore/syft:latest` controls what runs there. Moving one is a
commit that goes through review, not an environment variable somebody sets on a server. Update
deliberately with `docker buildx imagetools inspect <image>:latest`.

A remote agent reads a different set: `ZANSHIN_URL` and `ZANSHIN_AGENT_TOKEN` (both required),
plus `ZANSHIN_AGENT_WAIT` (`30s`), `ZANSHIN_AGENT_RETRY` (`10s`) and `ZANSHIN_AGENT_HEARTBEAT`
(`60s`). It reads no database variable at all, and cannot: see
[the agent section](#distributed-scanning-agents).



The database file is not part of the repository (it holds password hashes and encrypted SSH keys), so a fresh deployment starts with no accounts — hence the bootstrap variables. Once an account exists, they are ignored.

### Choosing a database

Four engines are supported — PostgreSQL, MariaDB, MySQL and SQLite — and **each is
exercised by the full integration campaign**. Flyway applies native migrations per dialect
under `db/migration/{vendor}/` (`postgresql`, `mariadb`, `mysql`, `sqlite`), ensuring complete
fidelity and avoiding dialect impedance mismatches. Point `ZANSHIN_DB_URL`
at the engine; it is read from the URL, and PostgreSQL is the default. A portability defect is
invisible to reading and to a single engine; running all four is the only way it gets found, and
it found several.

| | PostgreSQL | MariaDB | MySQL | SQLite |
|---|---|---|---|---|
| Transactional scan claim | yes | yes | yes | **no** |
| Complete claim batch under contention | yes | yes | **no** | n/a |
| Millisecond timestamps | yes | yes | yes | yes |
| `NULLS LAST` | yes | no | no | yes |
| Concurrent writers | yes | yes | yes | **no** |

Every "no" comes from a defect found by running, and **none of them raises an error**:

- **MySQL returns short claim batches.** Rows skipped by `SKIP LOCKED` count against the
  `LIMIT`, so a worker asking for two scans may get none while the queue is not empty. No
  row is ever handed to two workers — measured, not assumed — and the rest goes out on the
  next tick. It is a throughput characteristic, not a correctness defect. MariaDB, measured
  on the same scenario, returns a complete batch like PostgreSQL.
- **SQLite has a single writer.** A second instance on the same file would not be slow, it
  would corrupt data. Its claim therefore falls back to a conditional `UPDATE` guarded by
  the status column, which is correct for threads of one process. Its driver **refuses**
  `FOR UPDATE` rather than ignoring it. A driver that drops the clause silently produces a
  claim that looks transactional and hands the same scan to two processes.
- **Timestamps need declared precision on MySQL.** A bare `DATETIME` truncates to the
  second, which would make the audit chain fail its own verification and declare itself
  tampered with. `datetime(6)` is declared once in the changelog rather than
  column by column, and the connection is pinned to UTC for the same reason.

PostgreSQL remains the reference engine: the one where everything is true without
reservation, and the one the code picks by default.


## Installing a Semgrep rule set

Zanshin bundles one Semgrep rule. That is a licensing constraint, not an oversight:
`semgrep/semgrep-rules` was relicensed under terms that forbid redistributing the rules,
and the `opengrep-rules` fork carries a Commons Clause that would take Zanshin out of open
source and bind everyone who takes it up
([decision 0006](docs/architecture/decisions/0006-semgrep-rules-written-here.md)). So the
rules are fetched by you, from their author, and never redistributed here.

No tool ships for this. The steps are short enough not to warrant one:

```bash
# 1. Pick a tag and stay on it. A moving target makes scans irreproducible, and a rule
#    recategorized upstream destroys an issue's history — the rule id enters the
#    fingerprint.
TAG=v1.0.0
curl -fsSL "https://github.com/opengrep/opengrep-rules/archive/refs/tags/${TAG}.tar.gz" \
  | tar -xz -C /opt/zanshin

# 2. Read the licence before using it. LGPL-2.1 plus a Commons Clause: fine to run,
#    fine to build into your own agent image, NOT fine to publish that image.
less /opt/zanshin/opengrep-rules-${TAG}/LICENSE

# 3. Record what you installed, so a mass movement in the backlog has an explanation.
echo "opengrep-rules ${TAG} installed $(date -u +%FT%TZ)" > /opt/zanshin/rules-manifest.txt

# 4. Point Zanshin at it.
export ZANSHIN_SEMGREP_RULES_DIR=/opt/zanshin/opengrep-rules-${TAG}
```

Run once, at install time — **the scan itself stays offline**, which is the property that
makes it reproducible and deployable on an isolated network.

Two things to know:

- **The directory is merged, not substituted.** Your rules land beside the bundled one, in
  their own subtree, so a filename collision cannot silently replace a rule Zanshin ships.
- **A directory that cannot be read fails the SAST step**, leaving the previous findings
  untouched. It does not fall back to the bundled rule: Semgrep would exit cleanly with a
  shorter list, which reads as "analyzed, those issues are gone" and would resolve
  everything your rules had found — silently, on every target, the first time a volume is
  forgotten in a deployment.

## Tests

```bash
cd zanshin-java && ./gradlew build              # unit, architecture and HTTP suites
cd zanshin-java && ./gradlew integrationTest    # one engine, PostgreSQL via testcontainers
cd zanshin-java && ./gradlew integrationTestAll # all four engines — ten minutes, needs Docker
npm ci && npm run build && npm test             # the Angular interface
```

Around 840 unit tests, and five integration classes run against real servers. **CI runs the
first command and the Angular ones, and not the four-engine campaign**: it needs Docker and ten
minutes, and is run by hand before a release. A green tick does not mean portability was checked.

**The integration suites do not skip.** There is no "skip if the database is missing" guard,
deliberately: a suite that skips itself reports green having verified nothing. The harness starts
the container itself, so a missing Docker fails loudly — which is the correct behaviour, and
exactly the class of defect this project exists to find.

The changelog rather than `ddl-auto: update`, for the same reason: the schema under test is the
one production will receive.

The backend compiles under `-Werror` and a **layering test** (`ArchitectureTest`, ArchUnit)
that fails the build when an import crosses the wrong way. That test is not decoration: it is
what keeps the domain layer — fingerprints, gate verdicts, schedules — free of Hibernate and
HTTP, and therefore testable without a database.

One rule governs what is enabled: a gate that fires on noise is switched off within a week.
So the rules here are the ones whose findings were all real.

## Project structure

```
zanshin-java/
├── zanshin-common/          # Shared with the agent
│   ├── domain/              # Pure rules: fingerprint, gate, exports, schedule, payloads
│   └── scanning/            # Runs the scanners — no database
├── zanshin-core/            # The control plane
│   ├── persistence/         # JPA entities; the schema lives in db/changelog/
│   ├── repositories/        # Data access, no business rules — the only layer that speaks SQL
│   ├── services/            # Orchestration: ingestion, issues, notifications, tickets
│   └── api/                 # HTTP controllers
└── zanshin-agent/           # The remote worker. Does NOT depend on zanshin-core.
zanshin-angular/src/app/     # Angular: 17 page areas, Sakai layout over Optimus UI
docs/architecture/           # ADR
```

**`zanshin-agent` not depending on `zanshin-core` is a security property, not packaging.** No
JDBC driver is on its classpath, so it cannot hold a database connection — which it would need
`ENCRYPTION_KEY` for, and that key decrypts every deployment key Zanshin stores. The violation
fails to compile rather than failing review.

The import direction is enforced by `ArchitectureTest`:
`domain ← scanning ← persistence ← repositories ← services ← api`. The domain layer knows
nothing of Hibernate or HTTP, which is what makes the rules that matter — a fingerprint, a
gate verdict, a due date — testable without a database.


## License

Zanshin is licensed under the [Apache License 2.0](LICENSE) — patent grant included, and
contributions are under the same terms without a CLA. [`NOTICE`](NOTICE) lists the
third-party components the jar and the image bundle, including the two JDBC drivers that are
copyleft; both are `runtimeOnly`, and moving either onto the compile classpath changes the
legal position and not just the build file. The AGPL was the alternative and lost on
adoption — [decision 0012](docs/architecture/decisions/0012-apache-2-0.md) says on what
judgement, and what it would cost to reverse.

The licence covers the code, not the name: Apache-2.0 grants no trademark rights, so a fork
may use all of this and may not call itself Zanshin.
