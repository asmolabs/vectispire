# Notifications & Webhooks Integration Guide (Discord, Slack, Microsoft Teams)

Vectispire provides real-time alerting and notification delivery to inform development, security, and operations teams of critical security events: newly discovered vulnerabilities, Quality Gate failures, triage expirations, and completed scans.

---

## 📢 Supported Notification Channels

| Platform | Integration Type | Message Format | Security & Signature |
|---|---|---|---|
| **Discord** | Native Discord Webhook | Interactive Rich Embeds with severity color coding | URL hidden from non-administrators; unsigned |
| **Slack** | Incoming Webhook / Slack App | Block Kit JSON / Formatted text | URL hidden from non-administrators; unsigned — Slack would ignore a signature |
| **Microsoft Teams** | Power Automate / Workflow Webhook | Adaptive Cards / Structured JSON | URL hidden from non-administrators; unsigned — Teams would ignore a signature |
| **Generic Webhooks** | Custom HTTP POST Endpoint | Standardized scan delta JSON payload | `X-Vectispire-Signature` + `X-Vectispire-Timestamp`, when a signing secret is set |

---

## 1. 🟣 Discord Integration

Vectispire includes a specialized Discord channel (`DiscordNotificationChannel`) that formats security alerts into **Rich Embeds** with:
* Dynamic severity color bar:
  * 🔴 **Red** (`#DC2626`): **Critical** vulnerabilities
  * 🟠 **Orange** (`#EA580C`): **High** vulnerabilities
  * 🟡 **Yellow** (`#D97706`): **Medium** vulnerabilities
  * 🟢 **Green** (`#16A34A`): Clean scan / Resolved backlog
* Structured fields: Target repository/container, delta of new findings (+N), resolved findings (-N), and direct deep link into the Vectispire UI.

### Discord Setup:
1. In your Discord server, navigate to your channel settings > **Integrations** > **Webhooks**.
2. Click **New Webhook**, name it `Vectispire Bot`, and copy the webhook URL (e.g. `https://discord.com/api/webhooks/123456789/abcdef...`).
3. In Vectispire, go to **Settings > Notifications**.
4. Paste the URL into **Discord webhook URL** (`notification_discord_url`) and click **Save**.
5. You can trigger a live test message from the **Notification Center** page.

---

## 2. 🟢 Slack Integration

### Slack Setup:
1. Create a Slack App or enable **Incoming Webhooks** for your workspace:
   * Visit [api.slack.com/apps](https://api.slack.com/apps).
   * Enable *Incoming Webhooks* and click **Add New Webhook to Workspace**.
   * Pick your channel (e.g. `#secops-alerts` or `#dev-security`).
   * Copy the generated URL (`https://hooks.slack.com/services/T.../B.../...`).
2. In Vectispire (**Settings > Notifications**):
   * Paste the URL into **Slack webhook URL** (`notification_slack_url`), which posts Block Kit cards. The generic **Webhook URL** (`notification_webhook_url`) posts Vectispire's own JSON, which Slack does not render as a card.
   * No signing secret applies: Slack accepts whatever reaches an incoming webhook and checks nothing, so the URL itself is the credential — keep it out of tickets and screenshots.

---

## 3. 🔵 Microsoft Teams Integration

Microsoft Teams receives Vectispire alerts via **Power Automate** Workflow Webhooks:

### Teams Setup:
1. In Microsoft Teams, open your team channel > **Apps** > **Workflows**.
2. Search and select the template **"Post to a channel when a webhook request is received"**.
3. Copy the generated HTTP POST URL provided by Power Automate.
4. In Vectispire (**Settings > Notifications**):
   * Paste the URL into **Microsoft Teams webhook URL** (`notification_teams_url`), which posts an Adaptive Card, so nothing has to be mapped in the designer. **Enable Microsoft Teams notifications** (`notification_teams_enabled`) is the toggle beside it.
   * Messages to Teams are not signed, and a workflow triggered by a webhook request does not check a signature: the workflow URL is the credential.

---

## 🔒 SSRF Protection & Cryptographic Signing

* **Strict SSRF Guard (`OutboundUrlGuard`)**: Internal IP destinations (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) are refused by default unless `notification_allow_private_url` is explicitly allowed by an administrator.
* **What is encrypted, and what is not**: the **signing secret** (`notification_webhook_secret`) is a credential — encrypted at rest with AES-256-GCM, written only by its own route, returned by none. The **webhook URLs** (generic, Slack, Teams, Discord) are a capability rather than a credential: they are stored as written and hidden from non-administrators (`Sensitivity.SECRET`), not encrypted — and a team's own webhook URL is a plain column of `t_team_webhook`. Whoever can read the database can read them.
* **The SIEM export follows the same rule, over every protocol.** Its endpoint — a URL for the webhook, `host:port` for syslog over UDP, TCP or TLS — is refused on a private address unless `siem_allow_private_destination` is on — the export's own setting, which only an administrator may change — and a syslog host goes through the same address classifier as a URL. A SIEM collector on an internal network needs that setting; the connection test answers an outcome (delivered, refused by the policy, not delivered) and leaves the socket's error to the server log. Its authorization header is sent with the webhook only, encrypted at rest like the other credentials, and leaving the field empty when saving keeps the stored one. Events leave through the same outbox as notifications, after the change that caused them commits — see the [SIEM export](../../docs-site/integrations/siem.md) page and [decision 0025](../architecture/en/decisions/0025-siem-events-leave-through-the-outbox.md).
* **Replay Protection — the receiver's to enforce**: the signature covers `X-Vectispire-Timestamp` together with the exact body, so the timestamp cannot be rewritten; a replay is stopped only by a receiver that checks the signature, refuses a timestamp outside a window it chooses, and deduplicates on the payload's `message_id` within it. A receiver that does none of this — Slack, Teams, Discord — gets no protection from either header.
