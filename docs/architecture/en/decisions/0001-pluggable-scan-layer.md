# 0001 — The scan layer is pluggable behind `ScannerEngine`

**Date:** 2026-07-28 · **Status:** **superseded** by [0010](0010-one-scan-runner.md) on 2026-08-17 · **Decider:** Laurent Boucher

## Context

The scan pipeline called `docker.containers.run` directly, hard-coded, for Syft and then Grype. Adding an analysis type — secrets, IaC, SAST — or an execution mode other than Docker meant duplicating the orchestrator.

## Decision

A common interface, [`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java), which separates **what** to scan from **how and where** it is executed. The orchestrator calls the configured implementation; the Docker engine stays the default.

---

> **Superseded on 2026-08-17 by [0010](0010-one-scan-runner.md).** Only the Docker implementation was ever built. 0010 abandons the seam and records the remote agent as the extension point that survived.
