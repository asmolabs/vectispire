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
is on — using the Java runtime's trust store. A collector whose certificate comes from a private CA
needs that CA imported into the runtime's trust store (for the container image, a `cacerts` mounted
over the JVM's); there is no per-collector CA setting yet.

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

The connection test is always sent, whatever the threshold.

## Delivery

An event is written to the **outbox in the same transaction** as the change that caused it, and the
scheduler sends it **after that transaction commits** — within a minute by default. Nothing is sent on
the request path: a sign-in, a scan ingest or a sync never waits on your collector.

- **A change that rolls back sends nothing.**
- **A collector that is down is retried** with the outbox's backoff — eight attempts over about four
  hours — and then marked failed, where it stays visible.
- **Delivery is at least once.** A collector can accept an event and the record of that acceptance can
  fail, so an event can arrive twice. Deduplicate on `externalId`, which is the same on every copy.
- **The destination is read when the event leaves.** Fixing a typo in the endpoint delivers what was
  waiting; switching the export off abandons what was queued. Switching it off sends no "switched off"
  event — alert on the absence of the feed.
- **Security events come from the audit log.** An event exists when its audit entry does, and carries
  the same actor, address and target.

## Event catalogue

The signature identifier is a contract: correlation rules are written against it, and it will not
change meaning.

| Signature | Name | CEF severity | Emitted when |
|---|---|---|---|
| `ZAN-SEC-002` | Actively exploited vulnerability (KEV) detected | 10 | the threat-intelligence sync finds a watched finding newly listed by CISA KEV |
| `ZAN-SEC-003` | Security gate refused a build | 7 | a CI gate verdict fails |
| `ZAN-SEC-005` | Finding settled by triage | 5 | a finding is marked not affected or fixed without going through approval, by hand or by VEX import |
| `ZAN-SEC-006` | MFA backup code consumed | 6 | an emergency recovery code is spent |
| `ZAN-SEC-007` | Sign-in failure ceiling reached | 7 | the password throttle refuses an attempt |
| `ZAN-SEC-008` | MFA failure ceiling reached | 7 | a second-factor challenge is destroyed after too many wrong codes, or the account's second factor locks |
| `ZAN-SEC-009` | Bearer token failure ceiling reached | 7 | an address exhausts its allowance of refused tokens (once per window) |
| `ZAN-SEC-010` | Account privileges or credentials changed | 6 | an account is created, deleted, changes role, activation, password, second factor or visible targets — from the screen or SCIM |
| `ZAN-SEC-011` | Team access grant changed | 6 | a team's members or targets change |
| `ZAN-SEC-012` | API key issued | 5 | an integration key is issued |
| `ZAN-SEC-013` | API key revoked | 4 | an integration key is revoked |
| `ZAN-SEC-014` | Agent declared or its credentials changed | 6 | an agent is declared, enabled, disabled, deleted, or its signing key pinned or removed |
| `ZAN-SEC-015` | Agent result refused: attestation did not verify | 8 | an agent's signed result fails verification |
| `ZAN-SEC-016` | Four-eyes triage request approved | 5 | a second person settles a pending request |
| `ZAN-SEC-017` | Four-eyes triage request refused | 4 | a pending request is sent back |
| `ZAN-SEC-018` | Audit log integrity verification failed | 10 | a verification finds the hash chain broken or entries missing from the table |
| `ZAN-SEC-019` | Security-relevant setting changed | 6 | the SIEM export itself, a gate policy, visibility, four-eyes, a private-URL or remote-model switch, a tracker or model destination, or a stored credential changes |
| `ZAN-SEC-999` | SIEM connector health check | 1 | the connection test |

Single sign-on, the MFA requirement for single sign-on and the allowed Git hosts are set by
environment variables and change only with a restart, so they emit no event; their change is a
deployment, not a setting.

### CEF fields

```
CEF:0|Vectispire|ASPM|<version>|ZAN-SEC-007|Sign-in failure ceiling reached|7|rt=1790416800123 outcome=failure suser=alice src=203.0.113.7 act=LOGIN_BLOCKED cs1Label=Target cs1=alice cs2Label=UserAgent cs2=curl/8.5 externalId=5b1c… msg=Attempt refused by the throttle (300s to wait)
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
