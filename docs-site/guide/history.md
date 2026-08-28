# History and evidence

The history is the record of what was detected and what was decided, per target, kept for
the reader who has to be convinced after the fact and was not there.

## What it holds

Per repository, every scan, with:

- the **project version** that scan read;
- the issues that scan observed;
- every **triage decision** taken on them — from which status to which, by whom, with which
  justification, and against which version.

## Issues nobody triaged

An untriaged issue is printed as untriaged, explicitly.

That is a deliberate choice about what silence means. A history that simply omitted them
would let "nobody looked at this" pass for "somebody decided it was fine and did not write
it down". Those are different facts and an auditor is entitled to tell them apart.

## Exporting

Both **PDF** and **CSV**.

The PDF is written for a person: an auditor, a customer's security team, an insurer. The
CSV is for the analysis somebody wants to run themselves.

## Related

- [Issues and triage](issues.md) — how the decisions get recorded in the first place.
- [Audit log](../administration/audit-log.md) — the tamper-evident chain underneath.
- [Compliance](compliance.md) — the framework evaluation this record supports.
