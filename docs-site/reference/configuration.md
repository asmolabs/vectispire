# Configuration

Most settings live in the database and are edited from
[Settings](../administration/settings.md). What follows is what has to be right *before*
the application starts, because it is needed to reach that screen.

## Database

| Variable | Default |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:postgresql://localhost:5432/vectispire` — a **JDBC** URL. MySQL: `jdbc:mysql://localhost:3306/vectispire` |
| `VECTISPIRE_DB_USER` | `vectispire` |
| `VECTISPIRE_DB_PASSWORD` | empty |

The engine is read from the URL. There is no separate dialect setting.

## Encryption

| Variable | Notes |
|---|---|
| `ENCRYPTION_KEY` | Saving any secret is refused until this or the file form is set. |
| `ENCRYPTION_KEY_FILE` | A path to a file holding the key. **Prefer this in production.** Setting both is refused; an unresolvable path stops the application. |
| `VECTISPIRE_SIGNING_KEY` | The ECDSA P-256 private key (PEM, PKCS#8) that signs evidence bundles, VEX, CSAF, CycloneDX and in-toto envelopes; its public half is published at `/api/v1/crypto/public-key.pub`. Unset, a key is generated on first use and stored encrypted under `ENCRYPTION_KEY`, so it survives restarts — and nothing can be signed without `ENCRYPTION_KEY`. **Set it when more than one instance runs**, so they all sign with one key. A stored key that no configured `ENCRYPTION_KEY` can decrypt is refused, never replaced: replacing it would make every document already signed unverifiable. The shipped compose hands it over as the file `/run/secrets/vectispire.signing.key`, never as environment, and needs the variable declared in `.env` even when empty. |
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
| `VECTISPIRE_BOOTSTRAP_PASSWORD` | At least 8 characters. |

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
| `VECTISPIRE_API_KEY_REQUESTS_PER_MINUTE` | `600` | Requests per minute per [integration API key](../administration/api-keys.md); beyond it, `429` with `Retry-After`. Sessions and agents are not counted. |
| `VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW` | `300` | Deliveries per window and per address accepted on the inbound [tracker webhook](../integrations/ticketing.md); beyond it, `429` with `Retry-After`. Raise it if a tracker behind a shared egress makes bulk transitions larger than that. |
| `VECTISPIRE_WEBHOOK_REQUEST_WINDOW` | `PT1M` | The window of the setting above, as an ISO-8601 duration. |

Refused webhook deliveries are audited sparingly: the first from an address in ten minutes, once
more if that address reaches twenty, and at most a hundred entries in ten minutes overall. Every
refusal is still answered `401` or `403`.

## Request bodies

Three routes read their body whole before anything looks at it, and the sign-in routes can be
posted to by anyone. Past these limits they answer `413`.

| Variable | Default | Route |
|---|---|---|
| `VECTISPIRE_MAX_BODY_TICKET_WEBHOOK` | `1MB` | `POST /api/v1/tickets/webhook/{provider}` — a tracker event is tens of kilobytes |
| `VECTISPIRE_MAX_BODY_VEX_INGEST` | `16MB` | `POST /api/v1/vex/ingest` — a VEX document for a large product |
| `VECTISPIRE_MAX_BODY_AGENT_RESULT` | `256MB` | `POST /api/v1/agent/jobs/{id}/result` — the result carries the SBOM |
| `VECTISPIRE_MAX_BODY_SIGN_IN` | `16KB` | every `POST /api/v1/auth/…` — a login, a one-time code or a session exchange is a few hundred bytes |

## Cloning

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_GIT_ALLOWED_HOSTS` | *none* | Comma-separated hosts repositories may be cloned from — `gitlab.corp.example, *.corp.example`. Empty allows every host but link-local ones, which are always refused. Checked when a URL is entered and again before each scan. |

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
| `JAVA_TOOL_OPTIONS` | *none* | For a syslog-over-TLS collector signed by a private CA: `-Djavax.net.ssl.trustStore=/path/cacerts -Djavax.net.ssl.trustStorePassword=…`. The collector's name is verified against its certificate either way. |

## Branding

| Variable | Default |
|---|---|
| `VECTISPIRE_BRAND_NAME` | `Vectispire` — header, PDF reports, and SARIF / VEX / CSAF exports |
| `VECTISPIRE_GITLAB_URL` | `https://github.com/asmolabs/vectispire` — the source URL shown beside the "Powered by Vectispire" footer. The name is a leftover from when the project was hosted on GitLab; the setting is forge-agnostic and its default is not a GitLab URL. |

## API documentation

Swagger UI is **disabled by default in production**. Enable it in development:

```bash
export VECTISPIRE_SWAGGER_UI_ENABLED=true
export VECTISPIRE_API_DOCS_ENABLED=true
```

Then `http://localhost:3180/swagger-ui.html`.

## Remote agents

| Variable | Notes |
|---|---|
| `VECTISPIRE_URL` | The control plane the agent polls. |
| `VECTISPIRE_AGENT_TOKEN` | An API key with the `agent` scope, shown once at creation. |
| `VECTISPIRE_AGENT_SIGNING_KEY` | The private half of the Ed25519 key an administrator pinned for this agent, base64. Blank means results are accepted on the API key alone. Pinning one is what stops a stolen key from declaring a target clean — the empty result that resolves a whole backlog. |

How many scans an agent runs at once is **not** one of its variables: it is set on the agent's row
in the control plane, 1 to 16, and the agent reads it from every answer to its polls — see
[Running several scans at once](../administration/agents.md#running-several-scans-at-once).
`VECTISPIRE_SCAN_MAX_CONCURRENT` is the built-in worker's, and has no effect on a remote agent.

See [Agents](../administration/agents.md).
