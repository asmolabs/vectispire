# 0025 — SIEM events leave through the outbox, after commit, and their catalogue is a contract

**Date:** 2026-09-26 · **Status:** accepted · **Decider:** Laurent Boucher

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
  log says — including its address, which sign-in, MFA, the bearer ceiling and the gate resolve
  through the trusted proxies and the entries written through `RequestActors` do not yet.
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
