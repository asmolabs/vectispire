# 0010 — One scan runner, and the agent is the seam

**Date:** 2026-08-17 · **Status:** accepted · **Supersedes:** [0001](0001-pluggable-scan-layer.md)

## Context & Decision

A single concrete `ScanRunner` class executes containerized scanners. Remote agents serve as the primary distribution seam for offloading scanning execution.
