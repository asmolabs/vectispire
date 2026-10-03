# SIEM export

Vectispire forwards the security events a SOC watches for — an actively exploited vulnerability in
your estate, a build refused by the gate, a brute-force ceiling reached, a privilege or triage
decision, an audit log that no longer verifies — to your SIEM, in **ArcSight CEF**, over a webhook
or syslog.

It is configured under **Settings → Integrations → SIEM**, by an administrator or a security lead.

## Protocols and endpoints

The protocol decides the transport, and each protocol reads **one** endpoint format:

| Protocol | Endpoint | What travels |
|---|---|---|
| **Webhook** | an `https://` (or `http://`) URL | a JSON `POST` `{"cef": "<CEF line>"}`, redirects refused |
| **Syslog UDP** | `host:port` | one RFC 5424 message per datagram |
| **Syslog TCP** | `host:port` | RFC 5424, octet-counted (RFC 6587) |
| **Syslog TLS** | `host:port` | RFC 5424, octet-counted, inside TLS 1.2 or 1.3 |

`host:port` is a name or an IPv4 address and a port, for example `collector.example.com:6514`; an IPv6
address is written in brackets, `[2001:db8::1]:514`. There is no scheme — no `syslog+tls://` — and the
port is required, because the defaults differ by transport (514 for UDP and TCP, 6514 for TLS) and a
guessed port is a collector that receives nothing. A malformed endpoint is refused when you save, not
at the first event.

The syslog header carries facility 10 (`authpriv`), a severity derived from the CEF one (very high →
critical, high → error, medium → warning, low → notice), the instance's host name, `vectispire` as the
application and the CEF signature identifier as `MSGID`, so a collector can route on the header
without parsing the payload. The message has no byte-order mark: CEF parsers expect `CEF:0|` at the
first byte.

!!! warning "UDP gives no delivery guarantee"
    A datagram that leaves is recorded as delivered; the network may drop it and nothing says so.
    Use TCP or TLS when a missed event matters.

### TLS

The collector's certificate is verified **against the host name you typed** — hostname verification
is on, whatever the trust — using the Java runtime's trust store, or the **collector CA** you pin.

A collector whose certificate comes from a private CA no longer needs that CA in the runtime's trust
store. Paste the CA certificate, in PEM (`-----BEGIN CERTIFICATE-----`), into **Collector CA**, shown
for *Syslog TLS* only. It is then used **for this connection alone, and in place of the runtime's
store**: the public CAs are not trusted for the collector, and nothing else Vectispire connects to —
trackers, models, webhooks — trusts the pinned CA. A bundle of a root and its intermediates is
accepted, up to 8 certificates and 16,384 characters.

The save refuses what would not work or would trust too much: a certificate that is **not a CA**
(the collector's own certificate, which would make anybody holding a copy of it "trusted"), a CA
that has **expired or is not yet valid**, a CA whose key usage forbids signing certificates, anything
that is not a certificate — a private key pasted by mistake is refused and not echoed back — and a
CA sent with another protocol. A CA is public: it is stored as written, not encrypted, and shown
again with its subject and expiry. A pinned CA that expires later is not trusted any more: queued
events are abandoned with the reason "the pinned SIEM collector CA is unusable … expired", and the
fix is to paste the renewed CA.

Leaving the field empty removes a pinned CA; switching the protocol away from *Syslog TLS* removes it
too. Through the API, `tlsCaPem` absent from `PUT /api/v1/siem/config` keeps the stored one, so a
script written before the field existed does not unpin it. The connection test verifies against the
CA on the form, saved or not.

### The authorization header is for the webhook only

A webhook can carry an `Authorization` header — `Bearer <token>`, `Splunk <hec_token>` — stored
encrypted. A syslog frame has nowhere to put one, so the field is hidden for the syslog protocols and a
header sent with one is refused. Pointing the export at a new endpoint drops the stored header unless
you type it again: a header is issued for one collector.

### Private collectors

A collector on a private network — the usual case — is refused unless **Allow a private SIEM
destination** is on. That setting is the export's own and an **administrator's only**: the export is
configured and tested by a security lead, and the switch that decides how far it may reach is not in
the same hands. It is off by default. Until 2026-09 the export followed *Allow a private webhook URL*,
which a security lead may set; an installation whose collector is private needs an administrator to
switch the new setting on after upgrading, or events are refused and the outbox reports it.

The setting is the SIEM's own, not inherited from another channel's: neither *Allow a private
webhook URL* (notifications) nor *Allow a private tracker URL* opens the internal network to the
export. Changing it is audited (`SETTING_UPDATED`) and forwarded as `VECTI-SEC-019`.

The cloud metadata address, the Docker daemon's proxy and the database are refused whatever that
setting says, for syslog exactly as for the webhook: the address a name resolves to is checked once,
and the connection is made to that address.

### The connection test

The test sends the health-check event over the protocol on the form and answers one of three
outcomes: **delivered**, **refused by the outbound policy**, or **not delivered** — the collector
could not be reached or did not accept the event. The socket's own error — a refused connection, a
timeout, an HTTP status — is written to the server log, not answered: those tell a closed port from a
listening server, which would make the button a scanner of every network the export may reach.

## Minimum severity

Each event carries a CEF severity from 0 to 10. The minimum severity keeps the bands at or above it:

| Setting | Forwards |
|---|---|
| Critical | 9–10 |
| High (default) | 7–10 |
| Medium | 4–10 |
| Low | everything |

The severity compared is the event's. Every type has one fixed severity, given in the
[catalogue](#event-catalogue), except `VECTI-SEC-030`, which takes the late issue's: the threshold that
forwards an issue's severity forwards its breach.

The connection test is always sent, whatever the threshold.

## Delivery

An event is written to the **outbox in the same transaction** as the change that caused it, and the
scheduler sends it **after that transaction commits** — within a minute by default. Nothing is sent on
the request path: a sign-in, a scan ingest or a sync never waits on your collector.

- **A change that rolls back sends nothing.**
- **An event that cannot be written with its change does not cost the change.** For an event an
  audit entry signals, and for a gate refusal, the change is then written on its own and the event
  queued right after it, in a transaction of its own — the one case where a stop at the wrong moment
  can still lose an event, and the only one; the server logs a warning when it happens.
- **A collector that is down is retried** with the outbox's backoff — eight attempts over about four
  hours — and then marked failed, where it stays visible.
- **Delivery is at least once.** A collector can accept an event and the record of that acceptance can
  fail, so an event can arrive twice. Deduplicate on `externalId`, which is the same on every copy.
- **The destination is read when the event leaves.** Fixing a typo in the endpoint delivers what was
  waiting; switching the export off abandons what was queued.
- **Switching the export off, or pointing it at another collector, tells the collector being left.**
  `VECTI-SEC-028` is sent to it at once, over its own protocol, after the change is saved and whatever
  the minimum severity — it is the message that explains the silence after it. It names the account
  and the address that made the change, never the new destination. It is best effort: a collector
  that is down does not keep the export on. The change's audit entry says whether the notice arrived
  ("stop notice delivered to the previous collector", or "NOT delivered", the cause in the server
  log). A notice that never arrives is itself the case to alert on: keep alerting on the absence of
  the feed.
- **Security events come from the audit log.** An event exists when its audit entry does, and carries
  the same actor, address and target.

## Event catalogue

The signature identifier is a contract: correlation rules are written against it, and it will not
change meaning. Its prefix changed once, from `ZAN-SEC-` to `VECTI-SEC-`, in
0.10.0 — same numbers, same meanings; see the [release notes](../reference/release-notes.md#before-you-upgrade).

| Signature | Name | CEF severity | Emitted when |
|---|---|---|---|
| `VECTI-SEC-002` | Actively exploited vulnerability (KEV) detected | 10 | a synchronisation of the CISA KEV catalogue — every six hours, or asked from the threat-intelligence tab — finds an open issue whose CVE it newly lists. Once per issue: a CVE already flagged is not announced again, and one the catalogue stops listing is un-flagged without an event |
| `VECTI-SEC-003` | Security gate refused a build | 7 | a CI gate verdict fails |
| `VECTI-SEC-005` | Finding settled by triage | 5 | a finding is marked not affected or fixed without going through approval, by hand or by VEX import |
| `VECTI-SEC-006` | MFA backup code consumed | 6 | an emergency recovery code is spent |
| `VECTI-SEC-007` | Sign-in failure ceiling reached | 7 | the password throttle refuses an attempt — at sign-in, or when a signed-in account changes its password |
| `VECTI-SEC-008` | MFA failure ceiling reached | 7 | a second-factor challenge is destroyed after too many wrong codes, or the account's second factor locks |
| `VECTI-SEC-009` | Bearer token failure ceiling reached | 7 | an address exhausts its allowance of refused tokens — bearer or `X-API-Key` (once per window) |
| `VECTI-SEC-010` | Account privileges or credentials changed | 6 | an account is created, deleted, changes role, activation, password, second factor or visible targets — from the screen or SCIM |
| `VECTI-SEC-011` | Team access grant changed | 6 | a team's members or targets change, a repository is filed into a project or moved, or a project, repository or image that held grants is deleted |
| `VECTI-SEC-012` | API key issued | 5 | an integration key is issued |
| `VECTI-SEC-013` | API key revoked | 4 | an integration key is revoked — by hand, with the repository or image it was restricted to, or by a reset of its account's password (one event per key) |
| `VECTI-SEC-014` | Agent declared or its credentials changed | 6 | an agent is declared, enabled, disabled, deleted, its signing key pinned or removed, or its sealing key reset by an administrator |
| `VECTI-SEC-015` | Agent result refused: attestation did not verify | 8 | an agent's signed result fails verification |
| `VECTI-SEC-016` | Four-eyes triage request approved | 5 | a second person settles a pending request |
| `VECTI-SEC-017` | Four-eyes triage request refused | 4 | a pending request is sent back |
| `VECTI-SEC-018` | Audit log integrity verification failed | 10 | a verification finds the hash chain broken or entries missing from the table |
| `VECTI-SEC-019` | Security-relevant setting changed | 6 | the SIEM export itself, a gate policy, visibility, four-eyes, a private-URL or remote-model switch, a tracker or model destination, or a stored credential changes |
| `VECTI-SEC-020` | Agent sealing key refused: signature or generation did not verify | 8 | an agent's sealing key announcement is refused: its signature does not verify against the pinned signing key, or it is older than the key already accepted; no credential is sealed for it |
| `VECTI-SEC-021` | Analysis plugin registered, changed or activated | 6 | a plugin is registered, updated, enabled or disabled by the platform governor, allowed to run unsigned or no longer, or switched on or off for a project — third-party code gains or loses read access to some of the source |
| `VECTI-SEC-022` | SARIF import source declared or changed | 6 | a SARIF source is declared, enabled, disabled or removed: which key may deposit findings, for which project or repository, from which tools |
| `VECTI-SEC-023` | SARIF import refused: undeclared source, scope or tool | 5 | a SARIF upload is refused for what it claims — a key no source is declared for, a repository outside its source's scope, a tool its source is not declared for |
| `VECTI-SEC-024` | Checklist template version published or retired | 6 | a checklist template version is published, or a published one retired — what every project will attest to changes. Setting a draft aside is not signalled |
| `VECTI-SEC-025` | Checklist signed off | 5 | a project's checklist is signed off — a release attestation, and who gave it; the entry says whether four-eyes required the signer to be none of its authors |
| `VECTI-SEC-026` | Checklist sign-off refused or returned | 5 | a sign-off is refused because the signer is one of the checklist's authors while four-eyes is on, or because a proof stopped holding since the submission; or a submitted checklist is returned to its authors |
| `VECTI-SEC-027` | Report import refused: undeclared source, kind or scope | 5 | a coverage or test report is refused for what it claims — a key no enabled source is declared for, a kind its source is not declared for, a repository outside its source's scope |
| `VECTI-SEC-028` | SIEM export switched off or redirected | 7 | the export is switched off, or its protocol or endpoint changes: sent synchronously to the collector being left, whatever the minimum severity (see [Delivery](#delivery)) |
| `VECTI-SEC-029` | Secret leaked in source code | 8 | a scan finds a secret of high or critical severity that is not yet an issue — every secret the bundled scanner reports is graded high. Once per issue: the same leak seen by the next scan, or come back after being resolved, is not announced again. `cs3` carries the rule, `msg` the file; the matched value is never sent |
| `VECTI-SEC-030` | Remediation deadline passed | 3–8 | an open issue nobody has settled passes its remediation deadline (first seen + the severity's window — see [Remediation times](../guide/remediation-delays.md)). Noticed by the hourly maintenance turn, stamped with the deadline itself, once per issue. Only deadlines passed within the last seven days are announced, so the backlog already late at the upgrade — or after a window is shortened — is not announced at once; with the export off, a breach is not replayed when it is switched back on. **As severe as the late issue**: 8 for a critical, 7 for a high, 5 for a medium, 3 for a low — so the default minimum (High) forwards the critical and high breaches, Medium the medium ones too. An event still queued when upgrading from 0.10.0, where the severity was a fixed 6, leaves at 6 |
| `VECTI-SEC-032` | Project export left the platform | 4 | a project's whole triaged state was downloaded as its signed export ([Exports](../guide/exports.md#project-export)): who took it, which project (the target is the project's id), and the SHA-256 of `export.json` first in the message |
| `VECTI-SEC-999` | SIEM connector health check | 1 | the connection test |

`VECTI-SEC-001` and `VECTI-SEC-004` were once declared for a secret leak and an SLA breach and never
emitted; they stay retired. The events that now carry those meanings took new numbers, `029` and
`030`, so that a rule written against the old declaration does not start firing on a definition it
was not written for.

`VECTI-SEC-031` and `VECTI-SEC-033` are reserved for the report plugins of decision 0035 — a plugin
registered, changed, approved, activated or withdrawn; a plugin or its output refused — and are emitted
by no version yet.

Single sign-on, the MFA requirement for single sign-on and the allowed Git hosts are set by
environment variables and change only with a restart, so they emit no event; their change is a
deployment, not a setting.

### CEF fields

```
CEF:0|Vectispire|ASPM|<version>|VECTI-SEC-007|Sign-in failure ceiling reached|7|rt=1790416800123 outcome=failure suser=alice src=203.0.113.7 act=LOGIN_BLOCKED cs1Label=Target cs1=alice cs2Label=UserAgent cs2=curl/8.5 externalId=5b1c… msg=Attempt refused by the throttle (300s to wait)
```

| Field | Carries |
|---|---|
| `rt` | when it happened, in epoch milliseconds |
| `outcome` | `success`, `failure` or `detected`, fixed per event type |
| `suser` | the account that acted, as the audit log names it |
| `src` | the client address the audit entry recorded (see the note below) |
| `act` | the audit operation (`LOGIN_BLOCKED`, `API_KEY_CREATED`…), or `GATE_EVALUATED`, `AUDIT_VERIFIED` |
| `cs1` / `cs1Label=Target` | the resource acted upon — an issue, an account, a key, a setting, `repository 12` |
| `cs2` / `cs2Label=UserAgent` | the user agent of the request |
| `cs3` / `cs3Label=Identifier` | a CVE, for a KEV event |
| `cs4` / `cs4Label=Component` | the package, for a KEV event |
| `externalId` | the outbox message identifier — deduplicate on it |
| `msg` | the audit description, at most 1,024 characters |

The device version is the product version, empty when the build states none.

!!! note "`src` behind a load balancer"
    Sign-in, MFA, bearer-token and gate events resolve the client address through
    `vectispire.security.trusted-proxies` (see [Installation](../getting-started/installation.md)). Administrative changes — keys, settings, triage — record the
    address the server saw, which behind a load balancer is the balancer's. That is how the audit log
    records them today, and the event says what the audit log says.

Values are escaped as CEF requires — `\` and `=` in extensions, `\` and `|` in the header, line breaks
as `\n` and `\r` — and every other control character becomes a space. A username typed as
`x\nCEF:0|…|src=6.6.6.6` arrives as one line, with `src\=` escaped, and cannot forge a second event
or a field.
