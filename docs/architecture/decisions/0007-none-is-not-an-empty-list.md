# 0007 — An analyzer that fails returns `None`, never `[]`

**Date:** 2026-08-07 · **Status:** accepted

## Context

An analyzer can fail: image missing, timeout, unreadable output, out of memory. The
question is what it returns then.

The IaC scan returned `[]`. That is, **checkov crashing declared the repository
compliant**: the empty list was read as "analyzed, nothing found", so every open IaC issue
was resolved. On every affected target, silently.

The defect was not found by a review. It was found by deliberately breaking an image during
a real scan.

## Decision

`None` and `[]` say two different things, everywhere, and the code must tell them apart:

- **`[]`** — the step ran, it found nothing. Issues of that type are resolved.
- **`None`** — the step did not run. The backlog is left alone.

Consequently, `ScanArtifacts.iac` and `.sast` are `Optional`, and the scanned-types list
includes a type only if it was **actually looked for**.

And failure does not show only in the exit code: a Semgrep scan where most files timed out
exits 0 with a short list, which would read as "analyzed, almost nothing found". `errors[]`
and `paths.scanned` are inspected, and past an error threshold the result is `None`.

## What was rejected

**A `sast_ran` boolean alongside the list.** A boolean can lie about its payload: nothing
guarantees it is consistent with what it accompanies. `None` cannot.

And there is better: an agent on an older version leaves the field empty, hence `None`,
hence the right behaviour for free. If the delegation were forgotten in an engine, the
worst case would be a missing feature — with a server-computed boolean, it would be the
**silent resolution of the entire backlog** for that type.

## Consequences

This is the same distinction `ScanIngestor` already applied for end-of-life data; it is now
the rule.

The class of defect to watch for is nameable: **any default value that looks like success**.
An empty list, a zero, a `False` — each reads as a result when it means an absence. In an
application whose business is saying what is wrong, the default absence is always on the
reassuring side.

A scan in which one analyzer failed **still completes**, with the others' results. Refusing
the whole scan because one analyzer is broken would be the opposite reaction and just as
bad.
