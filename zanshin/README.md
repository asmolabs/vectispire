# Zanshin on the JVM

A port of the NestJS control plane to **Spring Boot 4.1 / JDK 25**, built with Gradle.

It runs **alongside** `backend/`, not instead of it. Both speak to the same schema, and the
NestJS implementation stays the executable reference the port is checked against: a contract
you can run is worth more than a contract you can read. It is deleted when parity is proven,
not before.

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
| The domain depends on no framework | `ArchitectureTest` |
| Only `repositories` speaks SQL | `ArchitectureTest` |
| Fingerprints match the ones already stored | `IssueFingerprintTest`, on the shared vectors |
| Entities agree with the schema, on four engines | `SchemaParityIntegrationTest` *(not yet ported)* |

The golden vectors under `backend/test/vectors/` are read **from the NestJS tree**, not copied
into this one. They were generated from the original Python implementation, and they are what
proves the fingerprint survived two ports unchanged. A copy would be a second file free to
drift from the first — and the drift would be invisible, both suites staying green while the
two backends disagreed about which issue is which.

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
| `IssueFingerprint` + golden vectors | done, 8/8 |
| Everything else | not started |

`ArchitectureTest` currently runs with `withOptionalLayers(true)` and `allowEmptyShould(true)`,
because layers that have not been ported yet are legitimately empty. **Both must be removed
once the port lands** — until then the suite proves less than it appears to, which is why it
is written down here rather than left in a comment.
