# Reading the results

The first scan of a real repository returns more than anybody will fix. That is normal, and
working through it in severity order is how a backlog stops being triaged at all. This page
is about the order that works instead.

## Findings, issues, state, triage

Four words, and mixing them up is the main source of confusion.

**Finding** — one observation from one scan. Ephemeral by nature.

**Issue** — the same problem tracked across scans: first seen, times seen, whether a fix
exists, what was decided. The fingerprint that identifies it deliberately ignores the
package version, so a dependency that stays vulnerable through three patch releases keeps
one history and one decision.

**State** — `open` or `resolved`. Written **only by the pipeline**, from what the scanners
observed on the last run.

**Triage status** — the VEX vocabulary: *affected*, *not affected*, *fixed*, *under
review*. Written **only by a person**.

Keeping state and triage apart is deliberate. If suppressing a finding marked it resolved,
"resolved" would stop meaning anything, and nobody could tell a problem that was fixed from
one somebody decided not to look at.

## Rank by exploitability, not by severity

A CVSS score says how bad a vulnerability would be if exploited. It says nothing about
whether anyone is exploiting it. Two enrichments answer that, and both are attached to
every vulnerability:

- **EPSS** — the probability that this CVE will be exploited in the wild in the next 30
  days.
- **CISA KEV** — whether it is *actively exploited*, as a matter of record rather than
  prediction.

A KEV entry with a medium CVSS outranks a critical nobody has ever exploited. The issue
list can be filtered on both.

## Then by what you can actually fix today

Each issue records whether your project **declared** the package itself or whether
something else pulled it in — direct versus transitive, read from the SBOM's dependency
graph.

The distinction is operational, not academic. A critical CVE in a declared dependency is a
version bump this afternoon. The same CVE four levels down waits on an upstream release
you do not control. Ranked identically they produce a backlog nobody finishes, so narrow
the list to what is fixable today and work that first.

Where the SBOM carries no dependency graph the answer is **unknown** — a missing answer
rather than a default one.

The **Fixable only** filter goes further: it hides everything with no fix version
published.

## What a scan changed

Each scan reports its delta: which issues are new, which are resolved. That is the view
worth reading on a recurring scan, because the standing total barely moves week to week
while the delta is where the news is.

For the trend rather than the snapshot, the dashboard's backlog-over-time series shows the
standing backlog day by day, what appeared against what was resolved, and the mean time to
resolve. That last figure is shown as **absent** rather than zero when nothing was
resolved, because a zero reads as "fixed the day it appeared".

## Two states with an empty backlog

An empty backlog passes every policy — including when it is empty because nothing ever ran.
The Security overview names the two cases that no other screen did:

- a target that was **never scanned**;
- a target whose **last scan failed**.

Both look green everywhere else. Check them before concluding anything from a clean
dashboard.

## Next

[Triaging issues →](../guide/issues.md) · [Failing a build on this →](../integrations/ci-gate.md)
