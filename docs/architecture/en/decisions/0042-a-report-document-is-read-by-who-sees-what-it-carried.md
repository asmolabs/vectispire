# 0042 — A report document is read by who sees what it carried, not only who sees the project now

**Date:** 2026-10-10 · **Status:** accepted · **Amends:** [0035](0035-report-plugins.md) §4 · **Builds on:** [0007](0007-none-is-not-an-empty-list.md) · **Decider:** Laurent Boucher

## Context

A report run builds the project's export at its claim, for its requester, over every target filed in the
project — repositories and images ([0035](0035-report-plugins.md) §2). The document it produces is kept for the
evidence window and downloaded by "whoever may read the run": a caller who sees the project **whole**, as the
project is **at the download** (§4). The status route (`GET /api/v1/report-documents/{sha256}`) answered by the
same rule.

The two instants are not the same project. A repository taken out of the project after the run left its findings
in the document, and a reader who sees the project as it now is — every target it holds today — but was never
shown that repository downloaded them. A grant naming the project resolves to its current targets, so a reader
granted the project is exactly such a reader. The audit of 10 October 2026 found it; nothing recorded which
targets an export had carried, so no rule could have been written against it.

## Decision

### 1. The run records the targets its export carried

`ProjectExportService` already reads the project's targets to refuse a caller who does not see them all. The
export a run is handed (`RunExport`) now carries that list, and the run's row keeps it in `export_targets`
(V87), each target as an issue's fingerprint names it — `repo:12 container:4` — written with the run's end in
the transaction that writes the rest of its record. It is not a new table: the list is read with the run, by the
run, and goes with it.

### 2. A document is read by a caller who sees the project whole **and** every target it carried

The download and the status route keep the project's rule and add the run's: every recorded target must be
visible to the caller (`ReportRunTargets.seenBy`). A caller who fails the second is answered as for a run that
does not exist — the run's 404 on the download, `unknown` on the status route — never 403: a different answer
would confirm what the document holds.

Both rules, not the second alone. Reading only the recorded targets would be more precise — a reader who lost
sight of a target added *after* the run would keep its earlier documents — but it would loosen the "whole
project" rule that 0035 applies to the export, the request and the runs alike, and that loosening deserves its
own decision rather than a correction's margin.

### 3. Not recorded is not empty

A run from before V87 has `export_targets` null: nobody wrote down what its export held. Filling the column from
the projects' current targets would record precisely the assumption this decision removes. Such a document is
read by a caller whose visibility is **everything** — an administrator, or every account while the deployment
leaves visibility open — and by nobody else ([0007](0007-none-is-not-an-empty-list.md)). Text in the column that
does not parse is read the same way, never as fewer targets. An empty column is an export over a project holding
no target, and asks nothing beyond the project's rule.

A target deleted since the run is visible to nobody restricted, so its document is read by those who see
everything — the same conservative answer.

### 4. The runs themselves stay under the project's rule

The list of runs and a run's record (plugin, state, instants, digests, counts) are not the document and keep
0035's rule. Hiding a run that exists from somebody who sees the project would make the screen disagree with
itself for little: the content is in the document.

## Consequences

- A reader who sees the project whole but not a target it held when the run was made no longer downloads that
  run's document, nor learns its standing. An administrator does.
- A reader who does not see a target added to the project since keeps losing the project's documents, as before:
  rule 2 keeps the project's condition.
- On an installation upgraded with documents already produced, those are read by administrators only (and by
  everybody while visibility is open). A new production starts with none.
- `ReportRunsRoutesTest` checks the download and the status route after a repository leaves the project, and a
  run whose targets were not recorded; `ReportRunTargetsTest` the column's text, an empty list and text that does
  not parse.

## Rejected

- **Record nothing, and check the targets the project holds now.** That is the rule that failed.
- **A table `t_report_run_target`.** Queryable, but nothing queries it: the list is read with its run. A column
  goes with the row it describes and needs no listener when a project is deleted.
- **Fill the column from the current projects at migration.** It writes down the assumption being corrected.
- **Only the recorded targets.** See §2: a loosening of 0035, for its own decision.
