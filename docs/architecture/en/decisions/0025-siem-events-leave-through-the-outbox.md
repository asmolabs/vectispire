# 0025 — SIEM events leave through the outbox, after commit, and their catalogue is a contract

**Date:** 2026-09-26 · **Status:** accepted · **Decider:** Laurent Boucher

> **Note (2026-09-28).** The SIEM signature identifiers this record names as `ZAN-SEC-nnn` are
> emitted as `VECTI-SEC-nnn` since the release after 0.9.0 — same numbers, same meanings. The text
> below is left as accepted; see the [SIEM catalogue](../../../../docs-site/integrations/siem.md#event-catalogue).

## Context

The SIEM export existed as a configuration screen and very little else. The settings offered four
protocols and a minimum severity; the exporter sent every event as an HTTP POST whatever the protocol
said, and read the severity nowhere. Its one method was `@Async` in a codebase with no `@EnableAsync`,
so it ran synchronously inside its caller — the threat-intelligence sync — before that transaction
committed: a POST holding the sync's locks for up to ten seconds, announcing a reclassification that
could still roll back. The catalogue declared seven events; one was ever emitted.

Three questions had to be answered together: how an event leaves, which events exist, and what a
SOC may rely on about both.

## Decision

- **An event is a row in `t_outbox_message`, written in the transaction that caused it** — type
  `siem_event` — and sent by the relay after the commit with the relay's claim, backoff and
  abandonment (`OutboxRetry`: eight attempts over about four hours). The relay was built for scan
  notifications; it now routes types that are not notifications to an `OutboxHandler`, so the SIEM
  shares the delivery policy without pretending to be a notification channel. An alternative — an
  after-commit callback that sends directly — was rejected: it loses the event on a crash between the
  commit and the send, retries nothing, and puts a network call back on the request thread.
- **One hook: the audit entry, after its own commit.** `AuditLogService` tells its listeners from the
  audit transaction's after-commit callback; `SiemEvents` queues an event for the entries that signal
  one. The operations that are unambiguous signal by themselves (`SecurityEventType.signalledBy`, an
  exhaustive switch); the ones too broad to — `LOGIN_BLOCKED`, `SETTING_UPDATED`, `ISSUE_TRIAGED`,
  `ACCESS_DENIED` — are named by their writer (`Record.signalling`). The three events with no audit
  entry behind them — a KEV reclassification, a gate refusal, a broken audit chain — are queued
  explicitly. Actor, address, target and action come from the entry, so an event says what the audit
  log says — including its address, which every entry resolves through the trusted proxies. (Until
  2026-09-26 only sign-in, MFA, the bearer ceiling and the gate did; the entries written through
  `RequestActors` and the access-denied handler named the peer. `ClientAddressFilter` now resolves the
  address once per request, and `ArchitectureTest` refuses a read of the peer outside
  `TrustedProxies`.)
- **At least once.** A collector can accept an event and the transaction recording it can fail; the
  event is then sent again. Each carries its outbox message id as CEF `externalId`, which is what a SOC
  deduplicates on. Over UDP, "sent" means handed to the network: nothing comes back.
- **The signature identifier is a contract.** A SOC writes correlation rules on `ZAN-SEC-0xx`; a
  changed identifier disarms them silently, in somebody else's system. Identifiers are frozen by a test,
  never reused, and the two that were declared and never emitted (001, 004) are retired. Only emitted
  events are listed.
- **One endpoint format per protocol.** A URL for the webhook, `host:port` for the three syslog
  protocols, port required, no scheme — a scheme would be a second place to state the transport.
  Syslog is RFC 5424, octet-counted (RFC 6587) over TCP and TLS, facility 10, the signature id as
  MSGID. A syslog host goes through the same address classifier as a URL
  (`OutboundUrlGuard.validateAndResolveEndpoint`) and the socket is opened to the pinned address. TLS
  verifies the host name against the JVM's trust store, TLS 1.2 at least.
- **The minimum severity maps onto the CEF bands** (critical 9–10, high 7–8, medium 4–6); empty or
  unreadable sends everything, and the connection test always passes. The authorization header is sent
  with the webhook only.

## Consequences

- An event reaches the collector within a relay interval (one minute by default), not at once. A
  collector that is down receives the backlog when it returns, within the four-hour budget; past it the
  row is marked failed and stays visible.
- A new `AuditOperation` or a new `Setting` does not compile until its author says whether it signals a
  SOC event — the switches have no default, deliberately.
- Switching the export off stops the stream silently: no "export disabled" event is sent, because the
  destination is read at send time and is gone. SOCs should alert on the absence of the feed.
- No custom CA for TLS: a private CA goes into the JVM's trust store. A per-collector CA is a follow-up.
- No migration: the outbox, the configuration row and their columns already fit.

## Amendment (2026-10-01)

Two of the consequences above were follow-ups, and are now done:

- **A per-collector CA** (`CollectorCa`, V63). A syslog-over-TLS collector may pin one or a few CA
  certificates, used for that connection alone and in place of the JVM's trust store; hostname
  verification is unchanged. Only current CA certificates are accepted, at the save and again at each
  delivery — the JDK does not check a trust anchor's own dates.
- **The stop is announced** (`VECTI-SEC-028`). Not through the outbox, for the reason given above —
  the destination is read at send time and is gone — but synchronously, by the save, to the collector
  being left, after the change is stored, whatever the minimum severity, best effort; the change's
  audit entry records whether it arrived. SOCs should still alert on the absence of the feed: a notice
  that never arrived is the case it covers.

The two retired identifiers stay retired: the secret leak and the SLA breach are emitted under new
numbers, `VECTI-SEC-029` (once per issue, at its creation, in the scan's transaction) and
`VECTI-SEC-030` (once per issue, by the hourly maintenance turn, deadlines passed within the last seven
days, V64), so that a rule written against the old declaration is not armed on a new definition.
