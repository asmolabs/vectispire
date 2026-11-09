# 0016 — CycloneDX is the generated SBOM; SPDX is not produced

**Date:** 2026-08-25 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

SPDX was listed as a supported supply-chain format in four documents and in the API description of
`GET /api/v1/scans/{id}/sbom`. The audit of 2026-08-25 established that **no SPDX document is
produced anywhere**. What exists is SPDX as a *licence vocabulary*: `Sbom` reads a component's
`spdxExpression` field as a fallback to `value`. There is no SPDX generator beside the CycloneDX,
CSAF and VEX ones, and no `spdxVersion` or `SPDXRef` is written by any code path.

So the choice was not "keep it or drop it" but "build it or stop claiming it", and three facts
decided which.

**The generated document already carries what SPDX 2.3 cannot express.** The CycloneDX endpoint is
`/api/v1/cyclonedx/scans/{scanId}/cyclonedx-vex.json`: the SBOM and the VEX statements in one
document. SPDX 2.3 has no vulnerability model at all — the security profile arrives in SPDX 3.0 —
so an SPDX 2.3 export would be the same inventory with the triage removed. Publishing it under a
second name would mean shipping a strictly less informative document and calling it parity.

**The raw endpoint is deliberately not a generated document.** `GET /api/v1/scans/{id}/sbom`
serves, byte for byte, what the cataloguer produced, because an SBOM that has been through a parser
and a writer is no longer what the cataloguer signed off. `DependencyScanner` invokes Syft with
`-o json`, so what it serves is Syft's **native** format — neither CycloneDX nor SPDX, whatever the
annotation said.

**A consumer who needs SPDX has a shorter path than we do.** Syft emits it directly
(`-o spdx-json`) from the same image Vectispire already pins. Producing it here would cost a second
container run per scan, or a second stored payload per scan, to hand back something the consumer
can generate themselves from the artefact they already have.

## Decision

**CycloneDX 1.6 with embedded VEX is the generated SBOM.** SPDX 2.3 documents are not produced,
and the claim is removed from the API description, from the four documents that carried it, and
from the compliance material.

SPDX **licence expressions** continue to be parsed, because that is a different thing wearing the
same name: it is how components declare their licence, and dropping it would break licence
governance.

The regulatory control is unaffected and was already correct in the code: `CRA-ART10-SBOM` requires
"an active, machine-readable SBOM" and names no format. It was only the documentation table that
had added "(CycloneDX & SPDX)".

## Consequences

**An integrator who needs SPDX must convert.** That is a real cost and it falls on them. It is
accepted because the conversion is one Syft invocation against an artefact they already hold, and
because the alternative was a second first-class format with no triage in it.

**The API description now names Syft's native JSON.** A description that promised a format the
endpoint never served is worse than a terse one: it is what an integrator builds against before
discovering the parse fails.

**When to revisit.** SPDX 3.0 changes the calculation, because its security profile can carry the
VEX statements 2.3 cannot — at that point SPDX stops being a lossy second copy and becomes a real
alternative. Also revisit if a customer's procurement process requires SPDX specifically, which is
a business fact rather than a technical one and should be recorded as such.
