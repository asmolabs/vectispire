# 0015 — One secrets engine

**Date:** 2026-08-25 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

The secrets step ran two scanners: gitleaks, and a second slot called *betterleaks*. The audit of
2026-08-25 established what that second slot actually was.

`ScannerImages` aliased `betterleaks` to the pinned `gitleaks` digest, and `BetterleaksScanner`
passed it the same `gitleaks.toml` with the same arguments. **By default it was the same engine
run twice**, differing only in the name of the report file — one more container per scan for
coverage of exactly nothing. That was fixed first, by skipping the second pass when the two images
match. The question left over was whether the seam should exist at all.

Three findings decided it:

**The seam is narrower than it looks.** `BetterleaksScanner` hard-coded the gitleaks command line
and the gitleaks rule file, so the only thing it could ever accept was a gitleaks-compatible image:
a fork, an internal mirror, a pinned older version. A genuinely different engine — TruffleHog,
detect-secrets, Nosey Parker — needs its own arguments and its own rules, and would not fit through
it.

**That narrow case is already covered.** Since images became configurable, naming
`vectispire.scanning.images.gitleaks` *replaces* the secrets scanner. Anyone wanting a fork or a
mirror does that, and gets one pass instead of two.

**Nothing exercised it.** No test ran the second engine against a real second engine; the suites
covered the decision to skip it. A seam with one implementation and no coverage is maintained by
whoever next reads it, which is the definition of a cost with no owner.

## Decision

One secrets engine. `BetterleaksScanner`, its image slot, its configuration entries and the merge
that existed to combine two result sets are removed.

## Consequences

**This follows [0010](0010-one-scan-runner.md) rather than departing from it.** That decision
abandoned a `ScannerEngine` interface with three implementations reduced to one, on the grounds
that a seam should not be rebuilt around a single implementation. This is the same shape, and
keeping it would have contradicted a decision taken for the same reason.

**What is given up.** Running two secret scanners simultaneously and merging their findings.
Nobody had asked for it, and the merge semantics it required were their own question: two engines
naming the same secret under different rule ids produce two issues, because `IssueFingerprint`
includes the rule identifier. That question goes away with the feature.

**What comes back if it is ever wanted.** Not this. A real second opinion needs a per-engine
argument template and a per-engine rule file — that is a scanner registry, which is a decision, not
a slot. It should reopen [0010](0010-one-scan-runner.md) with an argument, rather than reappear as
a second image name.

**What stays.** The signature that made the original defect impossible: both the removed scanner
and the remaining one returned bare `List`s merged inside a swallowed exception, so a failure read
as "analysed, found nothing" and *resolved* leaked-credential findings. `SecretsScanner` returns
`Optional`, `ScannerContractTest` asserts every container-running scanner does, and `ran(…)` will
not compile against anything else.
