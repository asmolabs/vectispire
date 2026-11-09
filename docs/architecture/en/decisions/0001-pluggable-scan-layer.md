# 0001 — The scan layer is pluggable behind `ScannerEngine`

**Date:** 2026-07-28 · **Status:** **superseded** by [0010](0010-one-scan-runner.md) on 2026-08-17 · **Decider:** Laurent Boucher

## Context

The scan pipeline called `docker.containers.run` directly, hard-coded, for Syft and then Grype. Adding an analysis type — secrets, IaC, SAST — or an execution mode other than Docker meant duplicating the orchestrator.

## Decision

A common interface, [`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java), which separates **what** to scan from **how and where** it is executed. The orchestrator calls the configured implementation; the Docker engine stays the default.

## What the alternative was, and what the seam cost

**The alternative was to keep the orchestrator hard-coded and duplicate it per analysis type.**
That was rejected on a forecast: secrets, IaC and SAST were expected within weeks, and each would
have copied the container lifecycle — pull, run with limits, collect, clean up — with its own
subtly different timeout handling. Four copies of that is four places for a sandbox setting to be
forgotten.

**What the seam cost was one indirection for one implementation.** Accepted knowingly: an
interface with a single implementor reads as speculative, and the argument for paying it was that
the second implementor was weeks away rather than hypothetical.

**The forecast was wrong, and that is the reversal's lesson.** The extra analysis types arrived as
*more scanner images behind the same Docker runner*, not as new runners — the thing that varied
was the tool, which `ScannerImages` already parameterised. The seam sat unused until 0010 removed
it. What the reversal shows is not that the seam was foolish but that the axis of variation was
mispredicted: the pluggable dimension turned out to be **where the runner executes** (the remote
agent), not **how**.

---

> **Superseded on 2026-08-17 by [0010](0010-one-scan-runner.md).** Only the Docker implementation was ever built. 0010 abandons the seam and records the remote agent as the extension point that survived.
