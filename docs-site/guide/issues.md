# Issues and triage

An issue is one problem, tracked across scans. It is where the work actually happens.

## What identifies an issue

The fingerprint deliberately **ignores the package version**. A dependency that stays
vulnerable through three patch releases is one issue with one history and one decision,
not three issues that each need deciding again.

Each issue carries: when it was first seen, how many times it has been seen, whether a fix
version exists, whether the package is direct or transitive, its EPSS score, its KEV
status, and its triage history.

## The two axes

| | Written by | Values |
|---|---|---|
| **State** | the pipeline, from what scanners observed | `open`, `resolved` |
| **Triage status** | a person | `affected`, `not affected`, `fixed`, `under review` |

They never write to each other. Suppressing an issue does not resolve it, and a scan
resolving an issue does not erase what somebody decided about it.

## Triaging

Open an issue and record a decision in the VEX vocabulary, with a **justification** and
optionally a **comment**. The justification is the part that has to survive you: "not
reachable in our configuration", "not shipped in production", "vendored code we do not
execute".

### Review dates

A suppression is a statement about a context, and contexts change. Set a **review date**
on the decision and the issue returns to *under review* at that date, with its
justification and comment intact.

This is the mechanism that stops a triage backlog from decaying into permanent silence.
"Not reachable in our configuration" was true when the configuration was what it was.

Issues past their deadline are flagged as such in the list.

### Bulk triage

One CVE across forty repositories is **one judgement about one context**, not forty — and
deciding it forty times is how triage stops happening.

Narrow the list with the filters, select, decide once. The transaction is all-or-nothing,
and each issue still records its own transition in its own history: a bulk decision that
silently rewrote forty rows would be indistinguishable from forty rows edited by hand, and
the record has to be able to tell the difference.

## Filters worth knowing

- **Fixable only** — hides everything with no published fix version.
- **Direct dependencies** — hides what an upstream release, not you, has to fix.
- **Actively exploited (KEV)** — the shortest list, and the one to read first.
- **Triaged / untriaged** — what has been decided against what has not.
- **Past its deadline** — suppressions whose review date has come round.

## Ordering that works

1. KEV entries, whatever their CVSS.
2. High EPSS.
3. Direct and fixable.
4. Everything else, by severity.

Severity-first ordering puts an unexploitable critical in a transitive dependency ahead of
an actively exploited high in a package you declared. That is the wrong afternoon's work.

## History

Every transition is kept: from which status to which, by whom, with which justification,
against which project version. An issue nobody triaged is printed in the exported history
saying so — silence would otherwise pass for a decision that was merely never written down.

See [History and evidence](history.md).
