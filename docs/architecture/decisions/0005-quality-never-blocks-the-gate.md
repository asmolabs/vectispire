# 0005 — Quality and AI review enter no verdict

**Date:** 2026-08-07 · **Status:** accepted

## Context

Two sources of findings are not of the same nature as the others.

**Quality analysis** (Semgrep, categories other than `security`) produces hundreds of
entries on a mature repository, in one afternoon, the moment it is switched on.

**AI review** produces findings from a model that has been handed the repository's code —
that is, from a model a hostile repository can dictate to.

Both feed the same backlog as the vulnerabilities, and the gate read everything.

## Decision

Neither enters a gate verdict. The filter is **in the policy gate's "is this considered"
check**, on the type — and there is **no policy flag** to allow it.

The absence of a flag is the decision, not an oversight. A flag would make "quality never
blocks" a lie: someone would only have to tick it for the guarantee to vanish, and the
sentence would stay written in the UI.

A confidence declared `LOW` additionally lowers the severity by one notch, which puts the
finding below the default gate threshold: visible in the backlog, unable to block.

## What was rejected

**A `fail_on_quality` flag, off by default.** See above.

**Deleting low-confidence findings.** A deleted finding disappears, then comes back as new
the day the rule's metadata changes — losing its triage. Lowering by one notch gives
exactly the wanted behaviour without lying about what was found.

**Lowering the severity of quality findings so they fall below the threshold.** That would
be a lie about severity, and it would end up in the SARIF export. Excluding them is
honest; disguising them is not.

## Consequences

The reasoning is the same in both cases, taken from two ends: **a gate that turns red on
the day it goes live is a gate that gets switched off by lunchtime.** What blocks a build
must be rare and defensible, otherwise the team learns to bypass the whole mechanism — and
they bypass the critical vulnerabilities too.

The partitioning does not stop at the gate, and that is the invisible half of the work.
Every place that enumerates finding types had to account for it: the counters at the top of
`/issues` (otherwise "1,847 issues to handle" on go-live day), the selection of
notifications (otherwise a webhook announcing hundreds of issues on the first scan), the
ticket-creation window (otherwise quality starves it indefinitely) and the SARIF export,
whose `tags` hard-coded `security` — **every quality finding would have been reported into
GitHub code scanning as a security alert**.
