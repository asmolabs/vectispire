# Notifications & Webhooks Integration Guide (Discord, Slack, Microsoft Teams)

Vectispire provides real-time alerting and notification delivery to inform development, security, and operations teams of critical security events: newly discovered vulnerabilities, Quality Gate failures, triage expirations, and completed scans.

---

## 📢 Supported Notification Channels

| Platform | Integration Type | Message Format | Security & Signature |
|---|---|---|---|
| **Discord** | Native Discord Webhook | Interactive Rich Embeds with severity color coding | Encrypted webhook URL |
| **Slack** | Incoming Webhook / Slack App | Block Kit JSON / Formatted text | HMAC-SHA256 signature supported |
| **Microsoft Teams** | Power Automate / Workflow Webhook | Adaptive Cards / Structured JSON | HMAC-SHA256 signature supported |
| **Generic Webhooks** | Custom HTTP POST Endpoint | Standardized scan delta JSON payload | `X-Vectispire-Signature` + `X-Vectispire-Timestamp` |

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
   * Paste the URL into **Notification webhook URL** (`notification_webhook_url`).
   * *(Optional)* Set a **Webhook Secret** (`notification_webhook_secret`) to enable HMAC-SHA256 payload signing.

---

## 3. 🔵 Microsoft Teams Integration

Microsoft Teams receives Vectispire alerts via **Power Automate** Workflow Webhooks:

### Teams Setup:
1. In Microsoft Teams, open your team channel > **Apps** > **Workflows**.
2. Search and select the template **"Post to a channel when a webhook request is received"**.
3. Copy the generated HTTP POST URL provided by Power Automate.
4. In Vectispire (**Settings > Notifications**):
   * Paste the URL into **Notification webhook URL** (`notification_webhook_url`).
   * If webhook signing is enabled, add an HMAC header validation step in your Power Automate workflow.

---

## 🔒 SSRF Protection & Cryptographic Signing

* **Strict SSRF Guard (`OutboundUrlGuard`)**: Internal IP destinations (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) are refused by default unless `notification_allow_private_url` is explicitly allowed by an administrator.
* **Encrypted at Rest**: Webhook URLs and signing secrets are encrypted using AES-GCM-256.
* **Replay Protection**: The `X-Vectispire-Timestamp` header combined with `X-Vectispire-Signature` guarantees message authenticity and prevents replay attacks.
