# vectispire-cp-outbox

The control plane's outbox in Rust — `core.outbox` (plan, Phase 2 task 2.2), ported from the Java of this branch's
tree (`vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/outbox/`, nine files, and
`OutboxRetry` in `vectispire-common`). In progress, not shipped: the Java control plane is the product. A **shared**
module, as Java declares it on `VectispireApplication`; its one edge is `maintenance`.

## What it does

- **`Outbox::enqueue(&mut Tx, payload, type, team) -> Uuid`** writes the row in the caller's transaction and never
  in one of its own (decision 0033): Java's `MANDATORY`, as a type. The message id is drawn first and stamped into the
  payload as `message_id`, because delivery is at least once and the receiver deduplicates on it. A payload that is
  not a JSON object is refused (Java fails its cast). One row per destination: `team_id` is whose channel the copy is
  for.
- **`Outbox::relay(limit)`** reads the due rows (pending, `next_attempt_at` unset or past, oldest first), **claims**
  each by a conditional update that repeats the due condition and pushes `next_attempt_at` five minutes ahead — no
  row lock; of two instances the second update changes nothing — then hands it to its type's handler (first) or
  channel, and settles it on its own: `sent`; or a failure recorded with the backoff (60 s doubling, one hour at most)
  and abandoned as `failed` on the eighth attempt; or, for a destination that is gone, abandoned at once with its
  reason. A type nobody delivers fails with Java's sentence (`IllegalStateException: No channel handles outbox type
  …`), is retried, then abandoned with it — never skipped. A delivery's failure never ends the pass; a store failure
  does, as Java's exception does.
- **`prune_sent`** deletes rows sent more than seven days ago; **`counts`** is the count per status.
- **`NotificationRelayTask`** (slot `NOTIFICATION_RELAY`, relay turn, batch of 20) and **`SentMessagesTask`** (slot
  `SENT_MESSAGES`, hourly) are composed by `crates/cp-app/src/maintenance.rs`.
- **`OutboxHandler`** and **`NotificationChannel`** are the contracts the relay dispatches to, implemented by the
  modules that own the destinations (agents in 2.9, notifications and SIEM in Phase 4, checklists and compliance in
  Phase 5). A destination returns `DeliveryError::Gone(reason)` or `DeliveryError::Failed { kind, message }`, where
  `kind` is the simple name of the exception Java's sender of the same destination throws, so `last_error` reads the
  same whichever control plane wrote it.

## The relay is held back

A relay that does not know a type retries its rows and abandons them after eight attempts. On a database Java wrote —
an upgrade, the drill on a copy, a switch back and forth — that destroys every pending message of the types the port
has not reached yet. The plan forbids it (§7, Phase 2: "the Rust binary does not start the relay turn until its
handler registry equals Java's"), and here is how that is held:

- `OutboxRegistryReferenceSetTest` (Java, a context test) writes `reference/outbox/registry.json` from the **started
  application** — the `OutboxHandler` and `NotificationChannel` beans Spring hands `OutboxService`, eleven types today
  — so a handler that lost its `@Component` is not counted. The file is compiled into this crate (`JAVA_REGISTRY`).
- `NotificationRelayTask::new(outbox, &java)` compares the outbox's `Registry` with it and keeps the `Coverage`:
  handlers and channels missing, and types Java does not relay (a row Java would abandon after a switch back). Only
  **equality** opens the relay; a channel registered as a handler is a difference too.
- A held task's run returns at once: it reads nothing and claims nothing, and says why once, at `warn`. The task is
  still composed, so the slot is filled and the composition test holds it; `crates/cp-app/tests/maintenance_composition.rs`
  asserts that the binary's relay **is held** today, and `tests/engines.rs` that a held relay leaves rows of every Java
  type untouched on both engines (beside the same rows, relayed by an open relay without their handler, retried with
  Java's reason — the damage the guard prevents).
- `Outbox::relay` itself has no guard: the tests exercise it with the handlers that exist, as the plan says.

Decided on 2026-10-17 by task 2.2. Opening the relay is adding the last handler, not a switch: when the registry
equals Java's, `is_held()` is false and nothing else changes.

## Held to Java

- `reference/outbox/relay.json`, written by `OutboxReferenceSetTest` **before** this code: the policy's constants, the
  backoff over every attempt count (a corrupted one included), the errors as `last_error` keeps them, the rows
  `enqueue` saves for twelve payloads, and twenty-five relay scenarios run through Java's `OutboxService` over a
  mocked repository — every repository call in order with its arguments, what each destination was handed, the pass's
  result. `tests/reference.rs` runs the same scenarios over a recording store (`OutboxStore` is the repository as a
  port for that reason) and requires the same calls.
- `tests/relay.rs`: `OutboxServiceTest`'s remaining cases and the guard.
- `tests/engines.rs`, MySQL 9.4 and PostgreSQL 17 migrated by `vectispire-migrate`: `OutboxDatabaseTest` (a rolled-back
  message never existed, never-tried is due, a claim is exclusive and lapses, a scheduled retry waits, pruning spares
  the pending), `OutboxClaimIntegrationTest` (eight instances reading the same twenty rows, each claimed once), two
  whole relays on two pools racing over sixty rows (each delivered once, none lost, none abandoned), the relay settling
  real rows, and **every row `enqueue` writes dumped column by column against the row Java's `enqueue` saves** — the
  payload byte for byte (hex), the instants at the microsecond.

`OutboxDatabaseTest.mandatoryMeansMandatory` has no port: an enqueue without a transaction does not compile.

## Differences from Java

Each decided on 2026-10-17 by task 2.2.

- **A channel is handed the stored text, not a parsed `NotificationPayload`.** The payload's shape is the
  notifications module's (Phase 4). Only the wording of `last_error` for a payload that does not parse differs:
  Jackson's sentence in Java, the channel's here; both retry and abandon.
- **A destination that panics fails its message** (`last_error` `panic: <text>`), as an exception does in Java,
  rather than ending the pass with the message claimed and its attempts never counted.
- **A double outside `[10⁻³, 10⁷)` in a payload is written as `ryu` writes it** (`0.0001`), where Jackson writes
  `1.0E-4`. Same number for every reader; no payload of the reference set has one. Everything else of the stamped
  text — member order, the replaced `message_id` kept in place, upper-case `\u001F`, DEL and U+2028 left raw — is
  Java's, byte for byte.

## Java quirks found, reproduced

- A `GoneDestinationException`'s reason is stored **whole and bare**: no `Kind: ` prefix, no 500-unit cut, unlike every
  other failure.
- `recordableError` cuts at 500 **UTF-16 units** and can split a surrogate pair; the drivers store the lone half as
  `?`. Reproduced as a `?`.
- The attempt counter wraps as a Java `int` (`wrapping_add`); a negative one gets the base backoff.
- `payloadOf`'s type check is unreachable: `channelFor` is evaluated first (the call's receiver before its argument)
  and throws for an unknown type, so the reason is always `No channel handles outbox type …`.
- Java's comments speak of twelve retries (`GoneDestinationException`, `OutboxService`); `MAX_ATTEMPTS` is eight.
- A store failure while settling escapes `relay`, which its javadoc says never throws; the maintenance turn catches it.
