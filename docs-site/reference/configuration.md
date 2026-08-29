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
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | Comma-separated older keys, tried **for decryption only**. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | The same list from a file, comma- or newline-separated. |

See [Rotation and purge](../administration/maintenance.md).

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

See [Agents](../administration/agents.md).
