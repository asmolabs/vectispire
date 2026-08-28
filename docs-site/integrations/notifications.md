# Notifications

Three destinations fire when a scan makes something **appear or reappear** — not on every
scan, which is what keeps the channel readable.

| Destination | |
|---|---|
| **Webhook** | your own endpoint, a bus, a SIEM |
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

An empty secret means unsigned, which is what an existing deployment stays until you set
one.

## Microsoft Teams

Teams is reached through a Power Automate **workflow**. The Office 365 connector it
replaces was retired.

Vectispire posts an Adaptive Card, so nothing has to be mapped in the designer — create
the workflow, take its URL, paste it in.

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
