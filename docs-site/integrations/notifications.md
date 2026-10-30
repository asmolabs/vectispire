# Notifications

Three destinations fire when a scan makes something **appear or reappear** — not on every
scan, which is what keeps the channel readable.

| Destination | |
|---|---|
| **Webhook** | your own endpoint, a bus — security events for a SOC have their own [SIEM export](siem.md) |
| **Microsoft Teams** | an Adaptive Card through a Power Automate workflow |
| **E-mail** | a distribution list |

They are **independent, not exclusive**. A team generally wants the card in its channel
*and* the mail on a distribution list, so each destination gets its own outbox row: a mail
server being down does not make Teams receive the message twice on the retry.

## Delivery you can rely on

The message is written to an **outbox in the same transaction as the scan's results**, and
delivered by the scheduler with capped exponential backoff.

That is the difference between a notification and a hope. A crash between the commit and
the POST used to lose the message silently; a briefly unreachable endpoint used to be
logged once and forgotten. Now the write and the intent to send commit together, or
neither does.

## Signed webhooks

Webhook messages can be signed: **HMAC-SHA256 over the timestamp and the exact body**, in
the `X-Vectispire-Signature` header.

Verify it if you can. It is what lets a receiver tell a message Vectispire sent from one
sent by whoever learned the URL — worth doing for a script, a bus or your own gateway.
Slack and Teams accept whatever arrives and cannot check it, so the signature buys nothing
there.

The timestamp is inside the signature, so it cannot be rewritten — but a replay is refused only
by a receiver that checks: reject a timestamp outside a window you choose, and deduplicate on the
payload's `message_id` within it.

An empty secret means unsigned, which is what an existing deployment stays until you set
one.

## Microsoft Teams

Teams is reached through a Power Automate **workflow**. The Office 365 connector it
replaces was retired.

Vectispire posts an Adaptive Card, so nothing has to be mapped in the designer — create
the workflow, take its URL, paste it in.

## When an integration token changes {#integration-token-alerts}

Since 0.11.1 the same channels are told when the [tracker token](ticketing.md#token-expiry) or a
[forge connection's token](../administration/forge-connections.md#token-expiry) **changes state**:
fourteen days before it expires, when it expired or the server refused it, and when it works again or
is no longer about to expire. Once per change, never once an hour; a restart says nothing again.

- **The installation's channels**: the global webhook, Slack, Teams, Discord and mail — each one
  configured, one outbox row each, as for a scan's delta. A team's own webhook is not told: the token
  is the installation's. The issue threshold does not apply; it is about findings.
- **The same rules**: the URL read at the send, the private-address switch, the webhook signature.
- **What it says**: the tracker by its kind (GitLab, Jira…) — never its address, a setting only
  administrators read — or the connection by its name with its server's address, the date or
  the status and since when, and a link to the screen where the token is replaced when the deployment
  knows its public address. **Never the token**, nor a header.
- **The webhook's body** is told apart from a scan's delta by `event: "token_state_changed"`, with
  `credential` (`tracker_token` or `forge_connection`), `name`, `reference`, `state` and
  `previous_state` (`none`, `expires_soon`, `expired`, `refused`), `signature_id` (the
  [SIEM event](siem.md#event-catalogue), `VECTI-SEC-038` to `040`), `expires_at`, `refused_status`,
  `refused_since`, `observed_at` and `message_id`.

The same change is in the audit log and sent to the SIEM — see the tables on the
[ticketing](ticketing.md#token-expiry) and [forge connections](../administration/forge-connections.md#token-expiry)
pages.

## The weekly posture report

Off by default, and it exists to cover the blind spot every other notification has.

Everything above fires when something *appears*. That is right for an alert and wrong for
a report: on a quiet week nobody is told anything, and a quiet week is also the week in
which a target has silently not been scanned for twenty days.

Once a week, to the webhook and the e-mail recipients: how much there is, which way it is
moving, and what was never examined.

It needs no outbox, unlike a scan delta. A report is derived from the database, so a failed
send is simply recomputed on the next tick.

## Configuring

**Notifications**, per destination: the URL or recipients, the secret where applicable,
and the events subscribed to.

## Each channel is an integration {#channel-integrations}

The five channels are integrations the platform governor switches on and off — `notification.webhook`
(the generic webhook, a team's own included), `notification.teams`, `notification.slack`,
`notification.discord` and `notification.mail`, all enabled to begin with — on
[*Administration → Integrations*](../administration/integrations.md), or through the API,
`PUT /api/v1/integrations/{key}/enabled` with `{"enabled": false}` ([decision 0040](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0040-integrations-are-switched-on-not-installed.md)).

**A channel with somewhere to send cannot be disabled.** Its URL set (for Teams, with its switch on),
its e-mail recipients set or the weekly checklist reminders on (mail), a team with a webhook of its own
(the generic webhook): the governor's switch is refused with 409 `integration-in-use`, and the refusal
lists what uses the channel. The alerts meant for it would otherwise be queued nowhere — lost in
silence, a quiet channel read as a quiet estate. Empty the channel first, then disable it.

**A disabled channel is unreachable.** It is absent from the Notification Center's list of channels; its
test is refused with 409 `integration-disabled`; giving it somewhere to send — its URL, recipients,
Teams' switch, the reminders, a team's webhook — is refused with 409 `integration-disabled`, and nothing
of that save is written. Emptying it is always saved. Nothing is queued for it, the weekly posture report
skips it, and the checklist reminders wait. Should a channel be off with a destination all the same (a
row changed by hand), what was queued for it is not sent and not lost: it waits in the outbox, pending,
the reason as its last error and no attempt counted, and leaves once the channel is enabled again.
