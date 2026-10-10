# Configuration

Most settings live in the database and are edited from
[Settings](../administration/settings.md). What follows is what has to be right *before*
the application starts, because it is needed to reach that screen.

## Database

| Variable | Default |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:mysql://localhost:3306/vectispire` — a **JDBC** URL; MySQL is the default engine, the one `docker-compose.yml` ships. PostgreSQL: `jdbc:postgresql://localhost:5432/vectispire` |
| `VECTISPIRE_DB_USER` | `vectispire` |
| `VECTISPIRE_DB_PASSWORD` | empty |

The engine is read from the URL. There is no separate dialect setting.

## Server and network

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_PORT` | `3180` | The HTTP port. The API, the interface and the agent protocol share it. |
| `VECTISPIRE_TRUSTED_PROXIES` | *none* | Addresses or CIDR ranges, comma-separated, whose `X-Forwarded-For` is believed. Empty means nothing is in front: the header is ignored and the peer's address is what the rate limiters and the audit log record. Behind a load balancer or an ingress, name it — otherwise every request arrives from it and the whole estate shares one rate-limit bucket. |
| `VECTISPIRE_PUBLIC_URL` | *none* | The base URL people reach this instance at. Named in a SARIF export's information URI and in a VEX document's identifier, so a document handed to somebody else says where it came from, and used for the links of e-mail notifications and project exports. |

## Encryption

| Variable | Notes |
|---|---|
| `ENCRYPTION_KEY` | Saving any secret is refused until this or the file form is set. |
| `ENCRYPTION_KEY_FILE` | A path to a file holding the key. **Prefer this in production.** Setting both is refused; an unresolvable path stops the application. |
| `VECTISPIRE_SIGNING_KEY` | The ECDSA P-256 private key (PEM, PKCS#8) that signs evidence bundles, VEX, CSAF, CycloneDX and in-toto envelopes; its public half is published at `/api/v1/crypto/public-key.pub`. Unset, a key is generated on first use and stored encrypted under `ENCRYPTION_KEY`, so it survives restarts — and nothing can be signed without `ENCRYPTION_KEY`. **On 0.10.0 that first use fails**: an installation without this key answers 500 on its first evidence bundle, because the key was created inside a read-only transaction (fixed in the release after 0.10.0, see the [release notes](release-notes.md)). On 0.10.0, set it. **Set it when more than one instance runs**, so they all sign with one key. A stored key that no configured `ENCRYPTION_KEY` can decrypt is refused, never replaced: replacing it would make every document already signed unverifiable. The shipped compose hands it over as the file `/run/secrets/vectispire.signing.key`, never as environment, and needs the variable declared in `.env` even when empty. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | Comma-separated older keys, tried **for decryption only**. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | The same list from a file, comma- or newline-separated. |

See [Rotation and purge](../administration/maintenance.md).

### Key custody in HashiCorp Vault

`VECTISPIRE_ENCRYPTION_KMS_TYPE=vault` encrypts through Vault's Transit engine instead of a local key,
with `VECTISPIRE_ENCRYPTION_VAULT_ENDPOINT`, `VECTISPIRE_ENCRYPTION_VAULT_TOKEN` (or `…_TOKEN_FILE`),
`VECTISPIRE_ENCRYPTION_VAULT_KEY_NAME` (default `vectispire`) and `VECTISPIRE_ENCRYPTION_VAULT_MOUNT_PATH`
(default `transit`). Asking for Vault without an endpoint or a token stops the application rather than
falling back to a local key.

**The Transit key must be derived**: `vault write -f transit/keys/vectispire derived=true`. Every secret
is encrypted with the row it belongs to as its context, so a ciphertext moved to another row does not
decrypt — and Vault uses that context only on a derived key, ignoring it on an ordinary one. Vectispire
reads the key once and **refuses to encrypt under a key that is not derived**; what such a key already
holds can still be read, with an error in the log, until the secrets are saved again under a derived key.

## First account

| Variable | Notes |
|---|---|
| `VECTISPIRE_BOOTSTRAP_USERNAME` | Used only when the user table is empty. |
| `VECTISPIRE_BOOTSTRAP_PASSWORD` | At least 12 characters. |

Once any account exists, both are ignored.

## Authentication

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_OIDC_ISSUER` | *none* | Enables [single sign-on](../administration/sso.md). |
| `VECTISPIRE_PASSWORD_LOGIN` | `true` | `false` delegates authentication entirely. **Ignored, loudly, with no issuer set** — it would leave no way in. |
| `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS` | `false` | Lets a privileged account (any role but USER) be linked on its first sign-on by its username; never one with a local second factor. Only for a realm where nobody chooses their own username. |
| `VECTISPIRE_OIDC_REQUIRE_MFA` | `false` | Refuses a single sign-on whose token states no second factor. A federated sign-in skips the local TOTP: the provider owns the second factor. |
| `VECTISPIRE_OIDC_MFA_AMR` | `mfa,otp,hwk,fido` | The RFC 8176 `amr` values that count as a second factor. |
| `VECTISPIRE_OIDC_MFA_ACR` | *none* | `acr` levels that count as one, when the provider signals MFA that way. |
| `VECTISPIRE_SESSION_LIFETIME` | `12h` | A session ends this long after it began, however active it has been — what bounds a stolen token's usefulness; no activity extends it. |
| `VECTISPIRE_SESSION_IDLE` | `60m` | A session ends after this long without a request — what protects an unlocked screen. |
| `VECTISPIRE_BEARER_FAILURES_PER_WINDOW` | `60` | Refused bearer tokens — sessions, agent and integration keys, the SCIM token — counted together per address; past it, the address is refused for the rest of the window and the audit log records it. Only failures count, so an agent polling with a valid key spends nothing. Generous on purpose: these tokens are long and random, and most of the control's value is the audit entry, not the refusal. |
| `VECTISPIRE_BEARER_FAILURE_WINDOW` | `PT5M` | The window of the setting above, as an ISO-8601 duration. |
| `VECTISPIRE_API_KEY_REQUESTS_PER_MINUTE` | `600` | Requests per minute per [integration API key](../administration/api-keys.md); beyond it, `429` with `Retry-After`. Sessions and agents are not counted. |
| `VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW` | `300` | Deliveries per window and per address accepted on the inbound [tracker webhook](../integrations/ticketing.md#inbound-webhook); beyond it, `429` with `Retry-After`. Raise it if a tracker behind a shared egress makes bulk transitions larger than that. |
| `VECTISPIRE_WEBHOOK_REQUEST_WINDOW` | `PT1M` | The window of the setting above, as an ISO-8601 duration. |

Refused webhook deliveries are audited sparingly: the first from an address in ten minutes, once
more if that address reaches twenty, and at most a hundred entries in ten minutes overall. Every
refusal is still answered `401` or `403`.

## Request bodies

Every request body is bounded while it is read, whether or not it declares its length. Routes not
named below take the default; a named route takes its own limit instead — larger or smaller — and
is never held to the default. Past its limit a route answers `413`, as a problem document whose
`detail` states the limit.

| Variable | Default | Route |
|---|---|---|
| `VECTISPIRE_MAX_BODY_DEFAULT` | `1MB` | every route not named below, whatever the method — a triage, a grant list, a setting or a SCIM user is tens of kilobytes at most |
| `VECTISPIRE_MAX_BODY_RULE_SET_UPLOAD` | `64MB` | `POST /api/v1/rule-sets` — a rule set may hold 32 MB of rule files, and the JSON carrying them escapes their YAML |
| `VECTISPIRE_MAX_BODY_TICKET_WEBHOOK` | `1MB` | `POST /api/v1/tickets/webhook/{provider}` — a tracker event is tens of kilobytes |
| `VECTISPIRE_MAX_BODY_VEX_INGEST` | `16MB` | `POST /api/v1/vex/ingest` — a VEX document for a large product |
| `VECTISPIRE_MAX_BODY_AGENT_RESULT` | `256MB` | `POST /api/v1/agent/jobs/{id}/result` — the result carries the SBOM |
| `VECTISPIRE_MAX_BODY_SIGN_IN` | `16KB` | every `POST /api/v1/auth/…` — a login, a one-time code or a session exchange is a few hundred bytes |
| `VECTISPIRE_MAX_BODY_SARIF_IMPORT` | `32MB` | `POST /api/v1/repositories/{id}/sarif-imports` — an internal tool's SARIF report for one repository; see [Plugins and SARIF imports](../administration/plugins.md) |
| `VECTISPIRE_MAX_BODY_COVERAGE_IMPORT` | `16MB` | `POST /api/v1/repositories/{id}/coverage-imports` — a JaCoCo or Cobertura report for a large repository is a few megabytes; only the totals are kept |
| `VECTISPIRE_MAX_BODY_TEST_REPORT_IMPORT` | `32MB` | `POST /api/v1/repositories/{id}/test-report-imports` — a JUnit document, or a zip of them, whose failures carry stack traces; the zip is bounded again once inflated |
| `VECTISPIRE_MAX_BODY_CHECKLIST_TEMPLATE_IMPORT` | `10MB` | `POST /api/v1/checklist-templates/{slug}/versions` — an organisation's checklist workbook, read whole and bounded again once inflated |
| `VECTISPIRE_MAX_BODY_SBOM_IMPORT` | `32MB` | `POST /api/v1/repositories/{id}/build-sbom-imports` — a build's CycloneDX SBOM, a few megabytes for a large multi-module build; read again up to 50,000 components — see [Importing a build's SBOM](../administration/plugins.md#importing-a-builds-sbom) |

## Cloning

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_GIT_ALLOWED_HOSTS` | *none* | Comma-separated hosts repositories may be cloned from — `gitlab.corp.example, *.corp.example`. Empty allows every host but link-local and other cloud metadata addresses, which are always refused. Checked when a URL is entered and again before each scan. |
| `VECTISPIRE_HOST_SSH` | `true` | A repository with no deployment key attached falls back to the scanning host's own `~/.ssh`. Set `false` wherever the people adding targets are not the people who own that key: the fallback is host-wide, so adding a URL is then enough to have it cloned with an identity nobody attached to it. `false` in the shipped `docker-compose.yml`, which mounts no `~/.ssh`. |

A clone over SSH with a deploy key checks the forge's host key against `<home>/.ssh/known_hosts` of
the executor: recorded at the first contact, refused when it changes, only matched against when the
file is read-only — see [Over SSH: the forge's host key](../guide/repositories.md#ssh-host-keys).
No ssh `config` is read for such a clone.

## Scan workspaces

A scan's workspace — and, unless set below, the vulnerability database — is created in the JVM's
temporary directory, then mounted into each scanner **by the Docker daemon, which resolves the path
on its own host**. When Vectispire itself runs in a container, that directory must therefore be a
host directory mounted at the **same absolute path**, or every scanner receives an empty directory.

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_WORK_DIR` | `/var/lib/vectispire/work` | `docker-compose.yml` only. The host directory mounted into the control plane at the same path, prepared for its user (1000:1000, 0700) by the `work-dir` service, and set as `-Djava.io.tmpdir` through `JDK_JAVA_OPTIONS`. Holds each running scan's clone and the matcher's database (some 3 GB), and under `home/` the process's home (`-Duser.home`), where the SSH host keys are recorded — the image's own home, `HOME=/home/vectispire`, is in the container's layer and does not outlive it. Outside the composition, do the same by hand. |
| `VECTISPIRE_AGENT_WORK_DIR` | `/var/lib/vectispire/agent-work` | `docker-compose.yml`, `with-agent` profile: the same for the agent, a directory of its own. |

## Scanners

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_IMAGE_SYFT`, `VECTISPIRE_IMAGE_GRYPE`, `VECTISPIRE_IMAGE_GITLEAKS`, `VECTISPIRE_IMAGE_CHECKOV`, `VECTISPIRE_IMAGE_SEMGREP` | *the pinned digest* | The image each scanner runs from, one by one. Blank keeps the digest Vectispire ships with — the reviewed one, in `ScannerImages`. Set them to pull from an internal registry, as an air-gapped estate must. Whoever overrides one takes on what the digest was protecting: a tag pulls whatever was pushed under it that morning, into a container that reads code nobody controls — **name a digest**, `registry.corp.example/anchore/syft@sha256:…`. Read by the control plane's built-in worker and, with the same names, by each agent. |
| `VECTISPIRE_IMAGE_SCAN_PLATFORM` | *none* | The platform pulled for a container image scan, e.g. `linux/amd64`. Empty lets the daemon pick its own architecture, so an arm64 machine would audit a variant nobody deploys. |

## Built-in worker and periodic jobs

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_EMBEDDED_WORKER` | `true` | `false` for a control plane that runs no scan itself: queued scans wait for a remote agent, and report plugins have no executor. |
| `VECTISPIRE_SCAN_MAX_CONCURRENT` | `2` | Scans this instance's built-in worker runs at once. Not an agent's: see below. |
| `VECTISPIRE_WORKER_LABELS` | *none* | Labels the built-in worker answers to. Empty on purpose: it then takes only work that requires no label. |
| `VECTISPIRE_WORKER_INTERVAL` | `15s` | How often the built-in worker looks for work. |
| `VECTISPIRE_SCHEDULER_INTERVAL` | `60s` | How often targets due for a periodic scan are looked for. |
| `VECTISPIRE_MAINTENANCE_INTERVAL` | `1h` | How often the maintenance tick runs — retention, expiring triage decisions, the ticket sweep, the threat-intelligence feeds and the rest of the housekeeping; each task keeps its own cadence within it (the KEV catalogue every six hours, EPSS daily). |

The outbox's interval, `VECTISPIRE_RELAY_INTERVAL`, is under [SIEM export](#siem-export).

## Vulnerability database

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_VULNERABILITY_DB_DIR` | *a directory in the temporary directory — `VECTISPIRE_WORK_DIR` in the composition* | Where the vulnerability matcher's database — some 3 GB — is downloaded **once for the host** and shared, read-only, by every scan; each scan used to download its own. One download at a time under a lock on this directory, published whole by an atomic rename, checked for updates hourly, and replaced generations deleted once no scan can still be reading them. The matcher itself runs with no network. A path on the Docker daemon's host, like the workspaces; a disk that survives a restart spares the first scan after one the download. |

## Plugins

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_PLUGIN_REGISTRY` | *none* | The internal registry every [plugin](../administration/plugins.md) image is pulled from — `registry.corp.example:5000/mirror`. The image's registry host is replaced and its path and digest are kept, so the mirror can serve a plugin but cannot substitute another. No scheme, no credential. Set the same on each agent. |
| `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` | `true` | The built-in worker runs no plugin whose manifest declares no [signer](../administration/plugins.md#signing-the-image), unless the platform governor [waived the requirement](../administration/plugins.md#running-an-unsigned-plugin) for that plugin: it is *refused* in the scan (`unsigned`), and nothing of it is started. A declared signer is verified with cosign before the pull whatever this says. `false` runs every unsigned plugin on this executor — prefer the per-plugin waiver. Each agent has its own. **A [report plugin](../administration/report-plugins.md) is not concerned**: its signer is always required. |
| `VECTISPIRE_REPORT_CONCURRENCY` | `2` | How many [report runs](../administration/report-plugins.md#requesting-a-report) this instance of the control plane carries out at once — each a pull, a signature check and a container of up to five minutes. Report plugins run on the control plane's container endpoint, under the built-in worker's switch: with `VECTISPIRE_EMBEDDED_WORKER=false` there is none, and a report request is refused. The plugins' mirror is `VECTISPIRE_PLUGIN_REGISTRY` above. |
| `VECTISPIRE_REPORT_INTERVAL` | `10s` | How often it looks for waiting report runs, and for runs an executor left behind. |
| `VECTISPIRE_DISCOVERY_CONCURRENCY` | `2` | How many [forge discoveries](../administration/forge-connections.md#discovering-repositories) this control-plane instance runs at once — each a listing of up to thirty minutes, sleeping on the forge's rate limits. Discoveries run on every instance, whatever `VECTISPIRE_EMBEDDED_WORKER` says, and never on an agent. |
| `VECTISPIRE_DISCOVERY_INTERVAL` | `5s` | How often it looks for waiting discoveries, and for runs an instance left behind. |

## Threat intelligence

The CISA KEV catalogue is read every six hours by the maintenance tick, FIRST's daily EPSS file once
a day, and both on demand from the **Threat Intelligence** settings tab. A scan reads the stored
copies and asks nobody: nothing about what a repository contains leaves the control plane, and an
estate without outbound access scans the same way once a mirror serves the two feeds.

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_KEV_URL` | CISA's `known_exploited_vulnerabilities.json` | A mirror for an estate that cannot reach `www.cisa.gov`. It must serve the whole catalogue in CISA's format: a document without its list, listing nothing, carrying fewer entries than its `count`, or older than the catalogue in use is refused, and the catalogue in use is kept — what a partial one leaves out would read as "no longer exploited". |
| `VECTISPIRE_KEV_ALLOW_PRIVATE` | `false` | `true` lets that URL resolve to a private or loopback address — a mirror inside the estate. Link-local (the cloud metadata endpoint) stays refused. A deployment property rather than a setting, so no session can point this call at the internal network. |
| `VECTISPIRE_EPSS_URL` | FIRST's `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | A mirror for an estate that cannot reach it — the file as FIRST publishes it, gzip or plain CSV, first line `#model_version:…,score_date:…`. One redirect to the same host is followed (FIRST's own address redirects to the day's file); any other is refused. A file that is cut short, has a malformed row or a score outside [0, 1], carries fewer than 100,000 scores or a tenth fewer than the file in use, inflates past 128 MiB, or is older than the file in use is refused, and the scores in use are kept. |
| `VECTISPIRE_EPSS_ALLOW_PRIVATE` | `false` | As `VECTISPIRE_KEV_ALLOW_PRIVATE`, for the EPSS mirror — each feed has its own switch, so opening the private network to one does not open it to the other. |

The tab shows, for each feed, when it was last read, what is in use — CISA's version and release
date of the catalogue, the EPSS model and the day its scores are for — and the last failed attempt
with its reason. Never synchronised, a scan marks nothing as actively exploited and gives no EPSS
score: unknown, never zero — the log says so at each scan. After an EPSS file is applied, the open
issues' scores are refreshed from it, so the gate, the scorecards and the EPSS ranking read today's.

## Audit

| Variable | Notes |
|---|---|
| `VECTISPIRE_AUDIT_MIRROR` | A path where each audit entry is appended as one JSON line, outside the database it watches. Off means the log has one copy, and the verification screen says so. |

## SIEM export

The export is configured on its [settings screen](../integrations/siem.md), not by variables, and so
is whether it may reach a collector on a private network: the administrator-only setting **Allow a
private SIEM destination**, off by default and separate from the notifications' private-URL switch.
Three things around it are the deployment's:

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_RELAY_INTERVAL` | `60s` | How often the outbox is drained — notifications and SIEM events alike, so the longest an event waits after its commit. |
| `HOSTNAME` | the machine's name | What the syslog header states as the sending host. Container runtimes set it. |
| `JAVA_TOOL_OPTIONS` | *none* | JVM options. A syslog-over-TLS collector signed by a private CA no longer needs `-Djavax.net.ssl.trustStore=…`: pin its CA on the SIEM card instead ([TLS](../integrations/siem.md#tls)), which trusts it for that connection only rather than for every outbound TLS connection. The collector's name is verified against its certificate either way. |

## Branding

| Variable | Default |
|---|---|
| `VECTISPIRE_BRAND_NAME` | `Vectispire` — header, PDF reports, and SARIF / VEX / CSAF exports |
| `VECTISPIRE_GITLAB_URL` | `https://github.com/asmolabs/vectispire` — the source URL shown beside the "Powered by Vectispire" footer. The name is a leftover from when the project was hosted on GitLab; the setting is forge-agnostic and its default is not a GitLab URL. |
| `VECTISPIRE_VEX_AUTHOR` | the brand name | The author a VEX document states. |
| `VECTISPIRE_VERSION` | *the build's own version* | The tool version exported documents state — SARIF, CSAF, CycloneDX, in-toto. Leave it unset: a version other than the artefact's makes the two unreconcilable where an assessor reads them. Set it only for a rebuild shipped under a version of its own. |

`VECTISPIRE_BRANDING_NAME` and `VECTISPIRE_INSTANCE_NAME`, earlier spellings of `VECTISPIRE_BRAND_NAME`,
are still read, in that order, when it is unset.

## API documentation

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_API_DOCS_ENABLED` | `false` | Serves the OpenAPI document, `/v3/api-docs`. |
| `VECTISPIRE_SWAGGER_UI_ENABLED` | `false` | Serves Swagger UI, `/swagger-ui.html`, which reads that document. |
| `VECTISPIRE_ANONYMOUS_API_DOCS` | `false` | Who may read them once served: closed by default, so a signed-in session is needed. `true` suits a public demonstration, or a deployment behind a gateway that already authenticates — a complete endpoint catalogue is the reconnaissance this product reports on other people's estates. |

Swagger UI is **disabled by default in production**. Enable it in development:

```bash
export VECTISPIRE_SWAGGER_UI_ENABLED=true
export VECTISPIRE_API_DOCS_ENABLED=true
```

Then `http://localhost:3180/swagger-ui.html`.

## Scan queue {#scan-queue}

| Variable | Default | |
|---|---|---|
| `VECTISPIRE_SCAN_RETRY_DELAYS` | `1m,5m,15m` | How long a scan waits, after an attempt that could not run for a transient reason — the network, a timeout, a lapsed lease — before it can be claimed again: the first after the first attempt, the last for every attempt past the list, bounded by the attempt limit (three). A permanent failure — a host key refused, a repository absent — fails at once and waits for nothing. Durations as Spring reads them (`30s`, `2m`); a negative one stops the application. |

## Remote agents

| Variable | Notes |
|---|---|
| `VECTISPIRE_URL` | The control plane the agent polls. |
| `VECTISPIRE_AGENT_TOKEN` | An API key with the `agent` scope, shown once at creation. |
| `VECTISPIRE_AGENT_WAIT` | How long one poll waits for work, `30s` by default; the server holds the request, so a queued scan leaves within the second. |
| `VECTISPIRE_AGENT_RETRY` | How long the agent waits before polling again after a failed poll, `10s`. |
| `VECTISPIRE_AGENT_HEARTBEAT` | How often a running scan's lease is renewed, `60s` — well under the lease, so one missed beat does not expire a scan that is progressing. |
| `VECTISPIRE_IMAGE_SYFT` … `VECTISPIRE_IMAGE_SEMGREP` | The scanner images on this agent, as for the control plane [above](#scanners). An agent on a closed network is where they usually point at an internal registry. |
| `VECTISPIRE_AGENT_SIGNING_KEY` | The private half of the Ed25519 key an administrator pinned for this agent, base64. Blank means results are accepted on the API key alone. Pinning one is what stops a stolen key from declaring a target clean — the empty result that resolves a whole backlog. |
| `VECTISPIRE_PLUGIN_REGISTRY` | The internal registry plugin images are pulled from on this agent — host relocated, path and digest kept. Blank pulls each from its own registry, which an agent on a closed network cannot reach: the plugin is then absent from the scan and its issues stay as they were. |
| `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` | On by default: this agent runs no plugin whose manifest declares no signer, unless the governor waived the requirement for that plugin — the task carries the waiver. `false` runs every unsigned plugin on this agent's host. A declared signer is verified before the pull either way. |
| `VECTISPIRE_VULNERABILITY_DB_DIR` | Where this agent keeps the vulnerability matcher's database, downloaded once and shared read-only by its scans — as for the control plane above. Blank is a directory in the temporary directory. |

How many scans an agent runs at once is **not** one of its variables: it is set on the agent's row
in the control plane, 1 to 16, and the agent reads it from every answer to its polls — see
[Running several scans at once](../administration/agents.md#running-several-scans-at-once).
`VECTISPIRE_SCAN_MAX_CONCURRENT` is the built-in worker's, and has no effect on a remote agent: it
counts the scans this instance's worker holds, never those the agents run.

See [Agents](../administration/agents.md).
