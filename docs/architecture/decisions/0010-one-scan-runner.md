# 0010 — One scan runner, and the agent is the seam

**Date:** 2026-08-17 · **Status:** accepted · **Decider:** Laurent Boucher · **Supersedes:** [0001](0001-pluggable-scan-layer.md)

## Context

Decision 0001 put a `ScannerEngine` interface between *what* to scan and *how and where*
it runs, with three implementations: Docker, a local side-car HTTP API, and OSV. It was
right at the time — the alternative was `docker.containers.run` hard-coded into the
orchestrator, which froze the Docker socket requirement into production and left nowhere
to plug a second analyzer in.

Only the Docker implementation was ever built, and the contract test that would have kept
three honest no longer exists. `ScanRunner` has been a single concrete class throughout, so
the register and the code have disagreed without either being revised.

This decision closes that gap by **abandoning the seam**, not by rebuilding it.

## Decision

There is one scan runner, `ScanRunner` in `zanshin-common/scanning/`, and it runs Docker
containers. No interface, no implementation registry, no engine configuration.

**The extension point that survived is the remote agent.** 0001's own consequences section
already noticed this: when remote agents arrived, an agent turned out to be a *transport*
for the scanning interface rather than an additional abstraction. That observation is now
the whole story — moving execution elsewhere is done by running an agent elsewhere
([0003](0003-long-polling-for-agents.md)), not by substituting an engine.

The two implementations that are not coming back, and why:

- **The local side-car HTTP API** was already documented as redundant with remote agents,
  which do the same job with a better trust boundary: a side-car needs the scanned code
  handed to a process on the same host, an agent claims work over an authenticated API and
  never touches the database.
- **OSV matching** bought little that a Grype image pinned by digest does not, and it
  moved the SBOM to a third party to get it.

## What was rejected

**Rebuilding the interface with one implementation behind it.** A seam with a single
implementation is not an extension point, it is a layer of indirection that has to be
maintained and cannot be verified — the contract test only meant something because three
implementations had to agree. Writing it back now would recreate the shape of 0001 with
none of its content, and the next reader would trust it.

**Leaving 0001 standing with a note.** The register's rule is that a decision that no
longer holds is superseded, not annotated. The note added on 2026-08-16 recorded the
divergence honestly, but a register where one page says "pluggable behind `ScannerEngine`"
and the code says otherwise is a register that gets checked once and then stops being
believed.

## Consequences

**The Docker socket requirement is back to being unconditional** for whichever process
runs scans. That is what 0001 set out to avoid, and it is worth stating plainly rather
than letting it be discovered: the mitigation is not an alternative engine, it is moving
execution onto an agent so the network-exposed process does not hold the socket. See the
open item on `VERISCAPE_ROLE` in [04](../04-runtime-and-deployment.md).

**Adding an analysis step is now an edit to `ScanRunner`**, not a new implementation. In
practice that is what every step added since 0001 has been — secrets, IaC, SAST were all
written into the Docker path.

**If a second execution mode is ever genuinely needed**, this decision is the one to
supersede, and the thing to reread is 0001's argument that a method an engine cannot
perform returns `null` rather than being abstract. That argument was sound and would still
apply.
