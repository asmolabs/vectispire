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
| `VECTISPIRE_SIGNING_KEY` | The ECDSA P-256 private key (PEM, PKCS#8) that signs evidence bundles, VEX, CSAF, CycloneDX and in-toto envelopes; its public half is published at `/api/v1/crypto/public-key.pub`. Unset, a key is generated on first use and stored encrypted under `ENCRYPTION_KEY`, so it survives restarts — and nothing can be signed without `ENCRYPTION_KEY`. **Set it when more than one instance runs**, so they all sign with one key. A stored key that no configured `ENCRYPTION_KEY` can decrypt is refused, never replaced: replacing it would make every document already signed unverifiable. |
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
| `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS` | `false` | Lets a SUPERUSER or ADMIN account be linked on its first sign-on by its username. Only for a realm where nobody chooses their own username. |
| `VECTISPIRE_OIDC_REQUIRE_MFA` | `false` | Refuses a single sign-on whose token states no second factor. A federated sign-in skips the local TOTP: the provider owns the second factor. |
| `VECTISPIRE_OIDC_MFA_AMR` | `mfa,otp,hwk,fido` | The RFC 8176 `amr` values that count as a second factor. |
| `VECTISPIRE_OIDC_MFA_ACR` | *none* | `acr` levels that count as one, when the provider signals MFA that way. |
| `VECTISPIRE_API_KEY_REQUESTS_PER_MINUTE` | `600` | Requests per minute per [integration API key](../administration/api-keys.md); beyond it, `429` with `Retry-After`. Sessions and agents are not counted. |

## Cloning

| Variable | Default | Notes |
|---|---|---|
| `VECTISPIRE_GIT_ALLOWED_HOSTS` | *none* | Comma-separated hosts repositories may be cloned from — `gitlab.corp.example, *.corp.example`. Empty allows every host but link-local ones, which are always refused. Checked when a URL is entered and again before each scan. |

## Audit

| Variable | Notes |
|---|---|
| `VECTISPIRE_AUDIT_MIRROR` | A path where each audit entry is appended as one JSON line, outside the database it watches. Off means the log has one copy, and the verification screen says so. |

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

See [Agents](../administration/agents.md).
