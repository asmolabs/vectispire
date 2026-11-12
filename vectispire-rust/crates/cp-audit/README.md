# vectispire-cp-audit

The control plane's audit module in Rust — `core.audit` and `common.domain.audit` (plan, Phase 1 task 1.6).
In progress, not shipped: the Java control plane is the product.

## What it guarantees, and what holds it

| Guarantee | Held by |
|---|---|
| An entry hashes to the bytes Java computes: NUL separator, field order, absent = empty, the instant in ISO-8601 UTC with exactly three fraction digits, truncated | `tests/reference_set.rs` against `reference/audit/chain.json` (written by `AuditChainReferenceSetTest`) |
| A chain Java started continues here, and one Rust extended continues in Java — also turn and turn about; each verifies the other's | `tests/oracle.rs`, both engines, the application's own `AuditLogService` |
| A Java and a Rust writer at once keep one unbroken chain | `tests/oracle.rs` (`java_and_rust_write_at_once`) — the `t_audit_chain_head` row lock serialises them |
| Two Rust instances at once keep one chain, instants strictly increasing | `tests/engines.rs` |
| Changing any column, deleting an entry somebody descends from, is found — Java's words | `tests/engines.rs`, `tests/oracle.rs` |
| The tip's deletion, which the chain cannot see, is found by the mirror | `tests/engines.rs` |
| The evidence bundle's `02_immutable_audit_log.jsonl` is Java's bytes | `tests/oracle.rs` (`the_bundle_lines_are_java_s_bytes`) |
| A Java JVM outside UTC changes nothing: Hibernate writes `Instant` as UTC on both engines | `tests/oracle.rs` (`a_java_writer_outside_utc_dates_its_entries_alike`) |

## How an entry is written

As `AuditLogService.write`: a transaction of its own; `select … for update` on `t_audit_chain_head`'s one row; the
head read under that lock, by `timestamp desc, id desc`; the entry dated after the head and after this instance's
last millisecond; every bounded column cut as Java cuts it (UTF-16 units, never half a pair), a blank address or
user agent stored as null, an absent resource as the letters `null`; the hash; the insert; the listeners in the
transaction; the mirror line; the commit. A lock conflict retries the whole transaction on `cp-db`'s backoff; a
listener's failure writes the entry again alone and tells the listeners after the commit. `record` never fails;
`append` returns why.

## What is outside the module

- **The mirror's file writer** is `vectispire-cp-runtime`'s `AuditMirror`: a module crate does not depend on the
  runtime, so `Mirror` is the seam and the binary adapts one to the other (`vectispire-cp-app`'s `audit_mirror`,
  held to the line's bytes by its tests). The binary does not open the database yet, so nothing constructs the log
  there today.
- **The SIEM** hears entries through `Listener` and broken verifications through `ChainBrokenListener`, both
  implemented by `vectispire-cp-siem`'s `SiemEvents`. The security-event vocabulary (`SecurityEventType`) is the
  domain crate's (`vectispire_domain::siem`); `Signal` carries its wire name, which `SiemEvents` reads back into it.
- **The routes** of the audit-log screen belong to the module that serves them.

## Running the suites

```sh
cargo test -p vectispire-cp-audit                     # the reference set and the live suite (Docker)
crates/cp-audit/oracle/check-oracle.sh                # against the real Java audit log (Docker, a JDK 25, Gradle)
```

The oracle runs `AuditOracle.java` source-launched on `vectispire-core`'s runtime classpath, which
`oracle/classpath.gradle` asks of Gradle once (`oracle/oracle.sh`). Containers are `vs-rs-aud-*`, removed after
each test; a missing prerequisite fails the run.

## Statements

**Checked: `sqlx::query!`, one module per engine** (`src/persistence/{mysql,postgres}.rs`), described while compiling
by a server of that engine migrated by the real Flyway, the answers kept in `.sqlx/`:

```sh
crates/cp-db/scripts/sqlx-prepare.sh check cp-audit     # regenerate, fail on any difference, compile offline
crates/cp-db/scripts/sqlx-prepare.sh prepare cp-audit   # after a statement or a schema change; commit the result
```

Each engine's statements are a feature (`mysql-queries`, `postgres-queries`, both on by default), as in `cp-db`. The one
text that is not checked is MySQL's `resource_id in (?, …)`, whose length follows the batch, as Hibernate expands a
collection — a JSON test would compare bytes where the column's collation compares without case; it runs on its
engine in the live suite.
