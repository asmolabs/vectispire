# Tracker tickets

Vectispire opens tickets in **GitLab**, **GitHub**, **Jira** or **ServiceNow** — one per problem that
would fail a build.

## One threshold, defined once

Ticket creation uses **the same gate policy** as the CI gate.

That is the design decision worth understanding. A separate ticketing threshold would mean
two bars to keep in step, and they would drift: teams would end up with tickets for things
that do not fail their build, or a red build with no ticket behind it. One policy, one
answer. See [Gate policies](../administration/gate-policies.md).

## No duplicates, ever

The tracker reference is kept **on the issue**.

So a tracker outage is retried rather than lost, and the retry finds the existing reference
and does not open a second ticket. The same issue seen on fifty consecutive nightly scans
is one ticket.

## Configuring

Under [Settings](../administration/settings.md): the tracker type, its URL, the project or
target, and a token.

Give the token the narrowest scope that can create and read issues in the target project.
It is stored encrypted with your `ENCRYPTION_KEY`, and storing it is refused before that
key exists.

## What lands in the ticket

Enough to act without opening Vectispire: the component and version, the identifier, the
severity, whether a fix exists, EPSS and KEV status, and a link back to the issue.

## Closing the loop

Closing the ticket in the tracker does not resolve the issue in Vectispire — `state` is
written only by the pipeline, from what the scanners observe. Fix the dependency, and the
next scan resolves it.

The other direction is automatic: when a scan resolves an issue, Vectispire closes the ticket it
opened for it. Each tracker is called with the verb its API routes for an update — `PUT` on
GitLab, `PATCH` on GitHub and ServiceNow, a transition on Jira — the one the issue's own workflow
offers towards a status in the *done* category, asked of Jira each time rather than assumed. ServiceNow addresses a record by
its `sys_id`, while the reference Vectispire keeps is the incident number people read
(`INC0012345`), so the number is first looked up in the incident table: the ServiceNow account
needs **read** access to `incident` as well as write.

If it is not going to be fixed, that is a [triage decision](../guide/issues.md), with a
justification and preferably a review date.

## The inbound webhook {#inbound-webhook}

A tracker can also call Vectispire back, at `POST /api/v1/tickets/webhook/{provider}` —
`gitlab`, `github`, `jira` or `servicenow`. When a ticket Vectispire knows by its reference is
closed as a false positive or as not going to be fixed, the call **proposes** a `not_affected`
decision on the issue; any other update is only recorded in the audit log.

**It is refused until a secret is set.** The route is the only one open without an account —
the tracker holds no session — so the secret is its whole authentication. While
**Settings → Tickets → Inbound webhook secret** is empty, every call is answered `403` with
*"The ticket webhook is not configured on this instance"*, which is what the tracker's delivery
log shows. Set the secret, then the same value in the tracker, presented the way that tracker
presents one:

| Tracker | Header | What it carries |
|---|---|---|
| GitLab | `X-Gitlab-Token` | the secret itself, GitLab's own *Secret token* field |
| GitHub | `X-Hub-Signature-256` | `sha256=` and the HMAC-SHA256 of the raw body, GitHub's own *Secret* field |
| Jira, ServiceNow | `X-Vectispire-Token` | the secret itself — neither has a convention, so this header is accepted for those two and no other |

A wrong or missing header is answered `401`, with no detail on which header was expected. A
stored secret that no configured key can decrypt refuses the same way: set it again.

**A delivery is acted on once.** The hash of each accepted body is kept for thirty days; the same
body arriving again within that window — a replay, or the tracker's own redelivery — is answered
`200` *"Delivery already processed"* and changes nothing.

**A decision is queued, never applied.** The issue moves to `pending_approval` with the proposed
status and its justification, and stays *under review* in the exported VEX documents until a
second person approves it under [four-eyes](../administration/four-eyes.md). The author recorded is
the integration (`GITLAB_webhook`, …); the name the tracker reports goes into the comment, as
reported data rather than as an identity.

Deliveries are limited per caller address (`VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW`, see
[Configuration](../reference/configuration.md)).
