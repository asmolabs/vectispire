# Zanshin on the JVM

A port of the NestJS control plane to **Spring Boot 4.1 / JDK 25**, built with Gradle.

It runs **alongside** `backend/`, not instead of it — the NestJS implementation stays readable
while the Java one is written, and is deleted once this one is complete.

**It is not a transliteration.** No instance of Zanshin has been run, so there is no stored
data to stay compatible with, and byte-for-byte fidelity is not a goal. Several constraints in
the TypeScript exist only because it had to match a Python implementation and a live database;
those are void. Where the original documents a compromise it was forced into, this port does
the right thing instead and says so. The reasoning in the comments is what carries over — not
the bytes.

```bash
./gradlew build                      # compile + unit tests + architecture suite
./gradlew integrationTest            # one engine, needs Docker (default: postgres)
./gradlew integrationTest -Pdialect=mariadb
./gradlew integrationTestAll         # all four
```

## Three modules, and why three

```
  zanshin-core  ──┐
                  ├──►  zanshin-common     domain calculations + scan execution
  zanshin-agent ──┘
```

`zanshin-common` holds what both sides must agree on: the calculations that *decide* — issue
fingerprint, gate verdict, audit chain, export formats — and the scan execution that turns a
checkout into artifacts. Both halves are needed by both sides: the agent fingerprints the
findings it reports, and the control plane runs the same scanners in its built-in worker. Two
copies of the fingerprint rule would be two answers to "is this the same issue", which is the
one question this system may not get wrong twice.

**The split is a security boundary, not packaging.** `zanshin-agent` does not depend on
`zanshin-core`, so no JDBC driver, no Hibernate and no Spring Data is on its compile
classpath. An agent holding a database connection would also need `ENCRYPTION_KEY`, which is
enough to decrypt *every* deployment key Zanshin holds; the property that justifies the
agent's existence is precisely what it does not have ([decision
0003](../docs/architecture/decisions/0003-long-polling-for-agents.md)). The NestJS tree
asserted this with a test that read the import graph. Here it is a fact about the build
graph: the violation does not fail review, it fails to compile.

**What that costs.** The layers *inside* `zanshin-core` — `persistence`, `repositories`,
`services`, `api` — can no longer be expressed by the module graph, so `ArchitectureTest`
enforces them with ArchUnit. That is a genuine step down: an ArchUnit rule can be deleted by
the same commit that violates it; a missing dependency cannot.

## What is checked, and where

| Guarantee | Enforced by |
|---|---|
| The agent cannot reach the database | the module graph, plus `AgentIsolationTest` |
| Layering inside the control plane | `ArchitectureTest` (ArchUnit) |
| The domain depends on no framework, and no Docker client | `ArchitectureTest` |
| Only `repositories` speaks SQL | `ArchitectureTest` |
| The fingerprint's identity rules hold | `IssueFingerprintTest` |
| The audit chain detects tampering, not concurrency | `AuditChainTest` |
| A caller can only tighten a gate policy, never relax it | `PolicyGateTest` |
| The metadata endpoint is refused however it is spelled | `OutboundUrlGuardTest` |
| A ciphertext moved to another row does not decrypt | `SecretCipherTest` |
| Entities agree with the schema, on four engines | `SchemaParityIntegrationTest` *(not yet ported)* |

### Two things the original could not fix, fixed here

**The fingerprint separator is NUL, not a vertical bar.** The NestJS version carried a note
saying the collision — a file path containing `|` imitating a field boundary — must *not* be
repaired, because changing the separator rewrites the identity of every stored issue and
destroys the triage attached to them. With no data, it costs nothing. This was the last moment
at which it was free.

**Closed sets are types.** `ScanTarget` is a sealed interface rather than two nullable ids that
a comment declares mutually exclusive; `FindingType` is an enum carrying `isSecurity()` rather
than seven string constants plus a hand-maintained list the constants could drift from.

### Cryptography

Passwords go through **Argon2id**; everything else hashes through `Digests`. Both are
**BouncyCastle**'s lightweight API rather than the JCA.

Argon2id replaces bcrypt, which the NestJS version used only to stay readable by a Python
implementation. That constraint dragged a real defect behind it: **bcrypt silently ignores
everything past 72 bytes**, so two passphrases sharing their first 72 were the same password,
and a validation rule had to refuse long ones rather than let anybody believe they were
protected. Both the truncation and the rule are gone.

The JCA is avoided for a separate reason. The JCA resolves an algorithm from whatever providers the JVM was started with, so
what actually ran becomes a property of the host — unacceptable for a hash that decides whether
an audit log was tampered with. Calling the engine directly also avoids registering a provider,
which is global mutable state in a process that also serves HTTP.

## Liquibase, and the check that has to stay

The schema is one changelog rather than one migration set per dialect. That is the requested
trade: less duplication, at the price of hiding where engines actually disagree — `tinyint(1)`
against `tinyint`, `timestamptz` against `datetime` — which is where all three divergences
found so far were.

`SchemaParityIntegrationTest` puts that difference back where it can fail: it asks Hibernate to
validate the entities against the schema the changelog really built, on all four engines
through Testcontainers. **There is no "skip if Docker is missing" guard, deliberately** — a
suite that skips itself reports green without having checked anything.

## State of the port

| | |
|---|---|
| Build, three modules, architecture suite | done |
| **`zanshin-common/domain` — the whole layer** | **done** |
| `zanshin-common/scanning` — workspace, container runner | in progress (the scanners remain) |
| `zanshin-core` — persistence, repositories, services, api | not started |
| `zanshin-agent` — the protocol | not started |

The domain layer is complete: every package under `backend/src/domain/` has a counterpart,
with one exception noted on purpose — `domain/common` held two timestamp helpers, and both
were replaced by what the JDK already provides (`Clock` for the first, `appendInstant(3)` for
the second). What survived is the *reason* the second existed, which now lives next to the
hashing it exists for.

`ArchitectureTest` still runs with `withOptionalLayers(true)` and `allowEmptyShould(true)`,
because `core`'s layers are not populated yet. **Both must be removed once the port lands** —
until then the suite proves less than it appears to, which is why it is written down here
rather than left in a comment.
