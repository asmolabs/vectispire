# vectispire-cp-siem

The control plane's SIEM module in Rust — `core.siem` (plan, Phase 4 task 4.2). Not shipped: the Java control plane is
the product. The domain (event catalogue, CEF line, syslog frame, endpoint, collector CA) is `vectispire_domain::siem`,
the first stage; the services the second; the three routes and the module's place in the binary the third. **Not here
yet**: the replay of the routes' recorded traffic — the fourth stage, with `golden/deferred/siem.txt`.

## What it does

| Rust | Java | |
|---|---|---|
| `SiemExporterService` | `SiemExporterService` | the singleton row: read, checked before it is touched, saved in its own transaction; the header encrypted under `siem_config:auth_header`, kept when blank, dropped when the endpoint moves; the collector CA read as pasted (`CollectorCa::parse_pasted`), kept when absent, removed when blank or when the protocol leaves TLS; the stop notice to the collector being left, synchronously, and the audit entry saying whether it arrived; the connection test's three outcomes |
| `SiemConfigView` | `SiemConfigView` | the row without the header's ciphertext, with the CA's subject and earliest expiry |
| `SiemEvents` | `SiemEvents` | `cp-audit`'s `Listener` (in the entry's transaction; `recorded` the fallback) and `ChainBrokenListener`; `enqueue(&mut Tx, …)` (`MANDATORY` as a type) and `publish` (its own transaction, never failing) |
| `QueuedEvent` | `SiemEvents.QueuedEvent` | the outbox payload, Java's members in Java's order |
| `SiemDelivery` | `SiemDelivery` | `cp-outbox`'s `OutboxHandler` for `siem_event`: gone (abandoned at once, with the reason) or retried |
| `SiemSender` | `internal.SiemSender` | webhook through `OutboundUrlGuard` and `PinnedHttpSender`; syslog through `validate_and_resolve_endpoint`; the private-destination switch read at every send |
| `SyslogSender` | `internal.SyslogSender` | UDP, TCP, TLS (rustls, TLS 1.3/1.2, hostname verified) to the addresses the guard checked; octet counting on a stream; one deadline over handshake and write |
| `persistence` | `SiemConfigEntity`, `SiemConfigRepository` | four checked statements per engine, `.sqlx/` kept by `crates/cp-db/scripts/sqlx-prepare.sh` |
| `Transport` | — | what the services send through: `SiemSender` in the binary, a recording one where the services are held to `SiemModuleReferenceSetTest`'s mocked `SiemSender` |
| `routes` (`web`) | `web.SiemController` | `GET /api/v1/siem/config` (governance read; the controller's literal — off, `WEBHOOK`, `HIGH`, every other member `null` — before the first save), `PUT /api/v1/siem/config` and `POST /api/v1/siem/test` (security lead); `InvalidInputException` 400, a missing encryption key 412, the KMS's address refused 422, anything else a referenced 500; the actor `RequestActors.of(principal, request, "system")` |
| `SecurityEvents` for `SiemEvents` | `SecurityEventRaised`, `SecurityEventRaisedApart` and their listeners | the port the issues and the gate raise their events through (below) |

## In the binary

`cp-app/src/siem.rs` composes it, and `main` calls those functions in this order: the sender (the guard built at start,
reserved endpoints included; `PinnedHttpSender` and `SyslogSender` over the runtime's trust; the private-destination
switch from the settings; `ProductVersion` as the CEF device version), the delivery and the events — then the audit log,
with the events as its listener — then the relaying outbox, whose registry holds `SiemDelivery` beside the agents'
handler — then the configuration's service, which records in that audit log. The events are also the verification's
chain-broken listener and the issues' and the gate's `SecurityEvents`. `cp-app/tests/siem_composition.rs` exercises
that composition on both engines: a save's audit entry, an event raised through the port and the chain's alarm reach a
UDP collector through the relay; a rolled-back raise does not; a collector on a reserved endpoint is refused whatever
the private switch says.

**Two outboxes, one table**: the audit log needs its listener when it is built, the listener an outbox, and the
relaying outbox a registry whose agents' handler writes to the audit log. `SiemEvents` only enqueues, which reads no
handler, so it is handed an outbox with an empty registry over the same `t_outbox_message`.

## Where a module raises an event — decided 2026-10-28

Java's `SecurityEventRaised` (in the raiser's transaction, `MANDATORY`) and `SecurityEventRaisedApart` (a transaction of
its own, never failing) are records in `common.domain.siem` published as Spring application events, so that `issues`,
`gate` and `threatintel` raise events without listing the SIEM among their dependencies. Rust has no event bus: the
publisher becomes a trait, **`vectispire_cp_outbox::SecurityEvents`** (`raise(&mut Tx, …)`, `raise_apart(…)`), which
`SiemEvents` implements and the binary hands in. Not `vectispire_domain`, which the agent links and which must not name a
transaction; not `cp-siem`, which would put the export back among the raisers' dependencies. The outbox is the shared
module the event becomes a row of, in the raiser's transaction — decision 0033's reading of the outbox — and a shared
module needs no line in a module's edges, exactly as the Java records needed none.

Wired in this stage: the issues' `SECRET_LEAK_DETECTED` (a secret graded high or above, raised in the scan's transaction
when its issue is created, never again), their `SLA_BREACHED` (raised in the breach sweep's batch transaction with the
mark that keeps it from being raised twice — the Rust sweep marked deadlines and announced none until now), and the
gate's `SECURITY_GATE_FAILED` (with its verdict in one transaction, or the verdict alone and the event apart). The threat
feed's `CRITICAL_KEV_DETECTED` comes with its module.

Module edges: Java's `@ApplicationModule(allowedDependencies = {"access::security"})`. The services use only the
shared modules (audit, outbox, outbound, settings, crypto), which need no line; `access::security` is for the routes —
the markers are `cp-http`'s in Rust, so what the routes take from it is `RequestActors` (`actor_name`), which Java keeps
beside the markers.

## What holds it

| | |
|---|---|
| `reference/siem/module.json`, `SiemModuleReferenceSetTest` (`vectispire-core`) | `tests/engines.rs`, on MySQL 9.4 and PostgreSQL 17: every payload sixteen entries and broken chains queue (the real listener in a real transaction, the row read back), what twenty-five stored rows become at delivery (the webhook body as `body()` writes it, the syslog message as `syslog::format` writes it, or the refusal), what forty saves write, refuse, audit and tell the collector being left, what eighteen connection tests answer and send |
| the wiring, with the real sender on loopback | `tests/engines.rs`: an audited action reaches a UDP collector after the relay; an event rolled back is never sent; a TCP collector that is down is retried and reached afterwards, octet-counted; the minimum decides what is queued, and an export switched off or without an endpoint queues nothing; a switched-off export abandons what was queued; the collector left behind is told, or the audit says it was not; a TLS collector is reached through its pinned CA and only through it; a lapsed CA abandons the row; the private switch decides the reach, and the test answers an outcome; the header is encrypted at rest under its context; an entry and its event commit together; a failing listener costs the entry nothing; the fallback queues after the commit |
| the transports, on real sockets | `tests/transport.rs` (`SyslogSenderTest`'s cases and more): UDP one datagram, TCP octet-counted, TLS through the pinned CA, the runtime's bundle, a pin replacing the bundle rather than joining it, hostname verification, the handshake deadline, a closed port, no checked address, the datagram ceiling; the webhook's bytes and headers, a blank header not sent, a non-2xx answer and rate limiting, the private switch |
| mutation | `security/mutants/p4-2b-siem-module.py` |

The TLS tests make a CA and a collector certificate per run with the `openssl` command, as `cp-outbound`'s do;
absent, they fail rather than skip.

## Differences from Java, on purpose

- **A queued row that does not read** is refused with serde's sentence after Java's prefix (`A queued SIEM event
  could not be read: …`), where Java gives Jackson's. Both retry and abandon it. A member of another JSON type — an
  extension value that is a number, a timestamp that is a string — is refused where Jackson would coerce it; neither
  control plane writes one.
- **A failure to read the configuration or the private switch** is recorded with the kind `DataAccessException`;
  Java records Spring's concrete subclass.
- **The syslog HOSTNAME** is `HOSTNAME` from the environment, else `uname`'s node name, else `-`; Java asks
  `InetAddress.getLocalHost().getHostName()`, which may answer a resolved name instead.
- **The runtime's trust for syslog over TLS** is the agent's and the control plane's one trust (`vectispire-tls`):
  the authorities compiled in, or `VECTISPIRE_TLS_CA_BUNDLE`'s certificates alone, read again from that path once at
  start because `TlsTrust` keeps reqwest's certificates. Java uses the JVM's truststore. The binary reads the variable
  for the SIEM's two senders and refuses to start on a bundle it cannot read; the webhook goes through the same trust.
- **The handshake and the write share one deadline**; Java gives the handshake `SO_TIMEOUT` (per read) and the write
  its watchdog. A collector that stalls is given up on either way.
- **The save writes the row in one transaction**, the read before it apart; Java's `findById` and `save` are two.
- **A `Signal` the catalogue does not hold** (a name, where Java's is the enum) is logged at error and the entry is
  read by its operation; Java cannot express one.

## Java behaviour reproduced that looks like a defect

- **The endpoint was checked trimmed and stored as typed** — fixed on the Java side the same day (`fix(siem): the
  endpoint is stored as it was checked, trimmed`), found by the reference case against a real `varchar(1024)`.
- **A syslog row keeps an authorization header it can never send** when the protocol changes and the endpoint's text
  does not: the header is dropped only when the endpoint moves. Unreachable from the screen (a webhook URL and a syslog
  `host:port` never have the same text), so reproduced and pinned (`a syslog collector left is told without a stale
  header`).
- **The connection test sends the typed header only**, never the stored one: a test with the header field left blank
  tests an unauthenticated webhook even when the export is configured with one.
- **The audit description of a save says nothing of the header**, by design (it is a credential); it cannot say either
  that the header was dropped because the endpoint moved.
