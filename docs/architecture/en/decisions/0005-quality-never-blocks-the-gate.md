# 0005 — Quality never blocks the gate

**Date:** 2026-08-11 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

Semgrep produces two kinds of finding from one pass. Each rule's `metadata.category` decides:
`security` becomes a `sast` finding, anything else becomes `quality`. The second kind arrives in
volume — style, complexity, dead code — on any repository that has not been linted to that
particular ruleset before.

A gate that fails on those is a gate that gets switched off. Not argued away: switched off, once,
by whoever is trying to ship on a Friday, and never switched back on. The security rules go with
it, because they were behind the same flag.

The AI review has a different problem with the same answer. A local model is handed the scanned
repository's own source code, and a hostile repository can steer a model it has been given the
source of. An invented `critical` would fail somebody's build on the say-so of text the audited
tree wrote.

## Decision

**Quality findings can never reach a gate verdict**, and that is a property of the finding type
rather than a policy flag:
[`FindingType`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/issues/FindingType.java)
declares `QUALITY` as `GateParticipation.NEVER`, so no configuration can admit it.

**AI review is `ON_REQUEST`** — tracked in the backlog, absent from the verdict until an operator
sets `include_ai_review`.

Everything else is `ALWAYS`: vulnerability, secret, IaC, license, EOL, sast.

## Consequences

**A new finding type has to declare where it stands**, because the enum requires it. That is the
mechanism that keeps this decision from decaying: adding a type without thinking about the gate is
not expressible.

**The distinction is not "important" versus "unimportant".** Quality findings are tracked, counted,
displayed and exportable. They are excluded from one specific consequence — failing a build —
because that consequence is what makes people disable the control that carries it.

**Both kinds come from the same run**, so they enter the scanned-types list together. A pass that
produced only quality findings still counts as SAST having run, and
[0007](0007-none-is-not-an-empty-list.md) applies to it normally.

**The AI review's exclusion is a security control, not a quality judgement.** It is why the prompt
wraps the sample in an explicit delimiter and asks the model to *report* an injection attempt
rather than obey it: that is a mitigation, and the reason its verdict blocks nothing by default is
that a mitigation is not a trust boundary.
