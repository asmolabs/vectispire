# 0001 — The scan layer is pluggable behind `ScannerEngine`

**Date:** 2026-07-28 · **Status:** **superseded** by [0010](0010-one-scan-runner.md) on 2026-08-17 · **Decider:** Laurent Boucher

## Context

The scan pipeline called `docker.containers.run` directly, hard-coded, for Syft and then
Grype. Adding an analysis type — secrets, IaC, SAST — or an execution mode other than
Docker meant duplicating the orchestrator.

Two immediate consequences: the deployment required the Docker socket with no possible
alternative, and there was nowhere to plug a second analyzer in without rewriting the
first.

## Decision

A common interface, [`ScanRunner`](../../../backend/src/scanning/scan-runner.ts), which
separates **what** to scan from **how and where** it is executed. The orchestrator calls
the configured implementation; the Docker engine stays the default, functionally
unchanged.

Three implementations today: Docker, a local side-car API, OSV.

**A method an engine cannot perform returns `None`; it is not abstract.** `None` is the
honest way for a back end to say "I don't do SAST". A sixth abstract method would break
the other two implementations and the contract test the day an analysis type is added —
that is, it would punish extension.

## What was rejected

**A third-party cloud API as the default engine.** It would bring enrichment and
reachability analysis for free, but the SBOM goes to the third party and — for the
analyzers that read code, secrets and SAST — so does the code. Cloud mode stays possible
and strictly opt-in; it is the default for nothing.

**Keeping the direct coupling to Docker.** That was the least immediate work. It froze the
Docker socket requirement into production, which is a root-equivalent privilege on the
host.

## Consequences

The extension point is at the right level, and it has stayed there: when remote agents
arrived, an agent turned out to be a **transport** for this interface, not an additional
abstraction. That is what made it possible to refuse a "plugin SDK" as the same thing
written twice.

The cost is a contract to uphold: `tests/scanners/test_engine_contract.py` checks that the
three implementations answer the same way. Without it, the engines would have drifted.

---

> **Superseded on 2026-08-17 by [0010](0010-one-scan-runner.md).** The NestJS port carried
> over only the Docker implementation, and the contract test named above went with the
> Python tree. Rather than rebuild the seam, 0010 abandons it and records the remote agent
> as the extension point that survived. The text above is kept as it was: it says what was
> decided at that date, and its argument about `null` rather than an abstract method would
> still apply if a second execution mode were ever needed.
