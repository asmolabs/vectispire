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
target, and a token. The URL, the project and the Jira account are an administrator's, like the
token: the token acts wherever they point it. A GitHub project is `owner/repository` and nothing
else — a path after it is refused when saved, and refused again at the send for a value stored
before.

Give the token the narrowest scope that can create and read issues in the target project.
It is stored encrypted with your `ENCRYPTION_KEY`, and storing it is refused before that
key exists. A tracker whose certificate comes from your own CA needs that CA pinned —
[below](#internal-ca).

## A tracker behind an internal CA {#internal-ca}

A self-hosted GitLab, Jira Data Center or ServiceNow on your network often carries a certificate
issued by your organisation's own CA, which the Java runtime's trust store does not hold. Before
0.11.0 every call to it failed the TLS handshake: no ticket was opened, and the hourly sweep retried
without saying why anywhere but the server log.

Paste that CA's certificate, in PEM (`-----BEGIN CERTIFICATE-----`), into **Settings → Tracker →
Tracker CA (PEM)** — the root, and its intermediates if your server does not send them; up to 8
certificates and 16,384 characters. To get it, ask whoever runs your PKI for the issuing CA's
certificate, or read the chain the tracker presents —
`openssl s_client -connect gitlab.example.internal:443 -showcerts < /dev/null` — and keep the
certificate of the CA at the top of it, **not** the server's own (the first one printed).

- **It applies to the tracker only.** Every call the integration makes — opening a ticket on any
  of the four trackers, closing it, Jira's list of transitions, ServiceNow's incident lookup — is
  verified against it; nothing else Vectispire connects to trusts it.
- **It replaces the runtime's store for the tracker, it is not added to it** — the same rule as a
  [forge connection's](../administration/forge-connections.md) and the [SIEM collector's](siem.md#tls) CA. The
  public CAs are then not trusted for the tracker: a certificate some public CA issued for its name
  does not pass. Leave the field empty for a tracker with a public certificate.
- **The tracker's name is still verified**: its certificate must name the host of the tracker URL.
  There is no "skip verification", which would hand the token to whoever answers first.
- **The save refuses what would not work or would trust too much**, in the forge connections'
  words: a certificate that is not a CA (the server's own), one that has expired or is not yet
  valid, one whose key usage forbids signing certificates, anything that is not a certificate — a
  private key pasted by mistake is refused and not echoed back.
- **It is an administrator's**, like the URL: it decides whom the tracker token is presented to.
  Other roles see the field read-only and without its value. Saving it is audited
  (`ticket_ca_pem changed`) and forwarded to the SIEM as a security setting change.
- **Shown by its subject and expiry.** Past that date the CA is not trusted any more: no ticket is
  opened or closed, the server log says the tracker CA expired, and the fix is to paste the renewed
  CA.

## When the token expires, or stops working {#token-expiry}

A tracker token does not last: GitLab now gives every token an expiry, a year at most by default.
Before 0.11.0 the day it lapsed the hourly sweep failed on every call, with a line in the server log
as the only trace, and no ticket was opened or closed again until somebody noticed.

The tracker card under **Settings → Integrations** now shows the token's life, as the
[forge connections' list](../administration/forge-connections.md) shows a connection's:

- **Its expiry, announced fourteen days ahead** — *Expires in 9 days*, then *Expired*. GitLab reports
  it (`GET /api/v4/personal_access_tokens/self`, for personal, group and project access tokens) and
  GitHub too (the `github-authentication-token-expiration` header of an authenticated call); both are
  asked when the token is saved and once a day after, through the tracker's [pinned CA](#internal-ca)
  when one is set. Jira and ServiceNow have no reliable way to say: enter the date yourself in
  **Token expiry date** (`ticket_token_expires_on`, `YYYY-MM-DD`, administrator-only), which also
  applies to a GitLab or GitHub token that reports none. Neither known, the card says *Expiry unknown*
  rather than nothing.
- **That it stopped working.** When the tracker answers a call of the sweep with `401` or `403` — an
  expired, revoked or under-privileged token — or the daily check with `401`, the card says *Stopped
  working* with the status and since when, before any date. It goes back to normal at the next call
  the tracker accepts, or when a new token is saved, which forgets everything known of the previous
  one.

Each change is written **once** to the server log at `WARN` — entering the fourteen days, expiring,
being refused, accepted again — never once an hour while nothing changes. Nothing is sent to a
notification channel or the SIEM, as for a forge connection's token: the screen and the log are where
it is said. `GET /api/v1/settings/ticket-token` answers `expiresAt`, `expirySource` (`reported`,
`declared` or `unknown`), `refusedStatus`, `refusedSince` and `checkedAt` beside `configured`, and
`PUT` answers the same once the tracker has been asked.

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

If it is not going to be fixed, that is a [triage decision](../guide/issues.md): **will not fix —
risk accepted**, with a review date and no VEX justification, since the product stays exposed.

## The inbound webhook {#inbound-webhook}

A tracker can also call Vectispire back, at `POST /api/v1/tickets/webhook/{provider}` —
`gitlab`, `github`, `jira` or `servicenow`. When a ticket Vectispire knows by its reference is
closed as not going to be fixed or as a false positive, the call **proposes** a decision on the
issue; any other update is only recorded in the audit log. The two closings are different claims, and
they are proposed as different statuses
([decision 0041](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0041-will-not-fix-is-not-not-affected.md)):

| The ticket is closed as | Proposed status | Justification |
|---|---|---|
| a refusal — Jira *Won't Fix*, *Declined*, *Rejected*; ServiceNow *Won't Fix*, *Risk Accepted*, *Withdrawn*; GitHub *not planned* (`state_reason: not_planned`); GitLab closed with *wontfix* or *won't fix* in its title | `will_not_fix` | none, and a review date proposed ninety days out |
| an explicit false positive — Jira *False Positive*, *Cannot Reproduce*; ServiceNow *False Positive*, *Not an Issue*; the words *false positive* in a GitHub issue's body or a GitLab issue's title or description | `not_affected` | `vulnerable_code_not_in_execute_path` |

**A refusal is never proposed as `not_affected`.** It says the team will not fix the vulnerability,
not that the product is safe from it; before 0.11.0 it was proposed as `not_affected` with
`inline_mitigations_already_exist`, a mitigation the tracker never mentioned, which the signed
documents would have carried once approved. GitHub's *not planned* is its only way to close without
completing, and says nothing about reachability, so it is a refusal and no longer a false positive.

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
status and its justification, and stays *under investigation* in the exported VEX documents until a
second person approves it under [four-eyes](../administration/four-eyes.md). The request keeps the
status the tracker asked for (`triageRequestedStatus`): the approver grants that status — a *Won't
Fix* as `will_not_fix`, never as `not_affected` — or turns the request down, and sets the review date,
which the dialog proposes from the request. The author recorded is
the integration (`GITLAB_webhook`, …); the name the tracker reports goes into the comment, as
reported data rather than as an identity.

**A decision a person settled is not moved by a ticket.** On an issue already `not_affected`,
`will_not_fix` or `fixed`, the tracker's word is recorded in the audit log and nothing changes. When
it disagrees with the settled status — *Won't Fix* on an issue cleared as not affected, a false
positive on an accepted risk — the entry is `TRIAGE_CONTRADICTED_BY_TRACKER`, sent to the SIEM as
[`VECTI-SEC-037`](siem.md#event-catalogue): one of the two is wrong, and only a person can say which.
A tracker that agrees is audited, not signalled.

Deliveries are limited per caller address (`VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW`, see
[Configuration](../reference/configuration.md)).
