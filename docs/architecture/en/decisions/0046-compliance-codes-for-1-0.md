# 0046 — The compliance codes 1.0 freezes: the CRA's as adopted, OWASP's 2021 edition

**Date:** 2026-10-29 · **Status:** proposed · **Builds on:** [0043](0043-what-1-0-promises.md) §6 · **Decider:** Laurent Boucher

## Context

[0043](0043-what-1-0-promises.md) §6 asks for the compliance codes to be settled before 1.0, because 1.0
freezes them: after it, renaming a code is a removal announced two minors ahead, or `/api/v2`. Two sets are
in question.

- **The CRA's codes use the 2022 proposal's article numbers.** `ComplianceFramework.EU_CRA` has
  `CRA-ART11-NOTIF`, `CRA-ART10-SBOM`, `CRA-ART10-LIFECYCLE` and `CRA-ART10-VULN`. Regulation (EU) 2024/2847
  as adopted moved those obligations: reporting to Art. 14, the manufacturer's obligations to Art. 13, the
  vulnerability-handling requirements to Annex I, Part II. The titles already cite the adopted text; the
  codes were kept on purpose, because they are stored with every control declaration
  (`ControlDeclarationEntity.controlCode`) and appear in the API, SARIF and the PDF report. So today an
  auditor reads `CRA-ART10-VULN` beside the words "Annex I, Part II (2); Art. 13(8)".
- **OWASP's categories are the 2021 edition's.** `OwaspTag` accepts only `A0n:2021` tags from rule sets,
  `OwaspCoverage.CATEGORIES` lists the 2021 titles, and the weekly coverage record stores a category per
  target and week. The 2025 edition renumbers and reshapes the list (supply-chain failures and exceptional
  conditions come in, SSRF folds into access control), so a 2021 category does not map one to one onto a
  2025 one.

## Decision

### 1. The CRA's codes are renamed to the adopted numbering, once, before 1.0

| Today | From the minor that carries this |
|---|---|
| `CRA-ART11-NOTIF` | `CRA-ART14-NOTIF` |
| `CRA-ART10-SBOM` | `CRA-ANNEX1-SBOM` |
| `CRA-ART10-LIFECYCLE` | `CRA-ART13-LIFECYCLE` |
| `CRA-ART10-VULN` | `CRA-ANNEX1-VULN` |

- **Each code names the provision its title cites first.** A code is what an auditor matches against the
  regulation, and a code that points at the wrong article is a finding in the audit it was meant to help.
- **Stored declarations are rewritten by a migration**, one `UPDATE` per code, and the upgrade drill's
  `ci/upgrade/accepted-rewrites.txt` lists it with this decision as the reason.
- **The API change is a break, accepted once.** `ci/openapi/accepted-breaks.txt` lists it; the release notes
  give the table above. It goes now, while 0.x allows it, rather than two minors after 1.0.
- **The other frameworks' codes stay.** NIS 2's Art. 21, ISO 27001:2022's Annex A, DORA's articles, PCI DSS
  v4.0's requirements and SOC 2's criteria match the texts their titles cite.

### 2. OWASP stays on the 2021 edition for 1.0; 2025 comes later, beside it

- **1.0 freezes the 2021 identifiers** (`A01`…`A10` with the 2021 titles) in the API and in the weekly
  record. Rule sets in use are tagged with the 2021 edition, and the audit questionnaires the coverage page
  answers still ask about it.
- **The 2025 edition arrives in a 1.x minor, additively**: a second field or a second view beside the 2021
  one, from a mapping that says where a 2021 category splits or merges. Adding it is allowed by
  [0043](0043-what-1-0-promises.md) §1; replacing the 2021 one would not be.
- Nothing to do before 1.0 except saying so on the coverage page and in the compliance guide: "OWASP Top 10,
  2021 edition".

## Consequences

- One minor release (0.12 or 0.13) carries a migration that rewrites stored CRA codes, an accepted API break,
  and a release note with the table. Its estimate in the 1.0 plan is two to three days.
- A pipeline or report template matching on a CRA code changes once. One matching on an OWASP category does
  not change at 1.0.
- The documents that list the codes (`docs/{en,fr}/COMPLIANCE_AND_REGULATORY*.md`, the compliance guide in
  `docs-site/`) change in the same pull request.

## Rejected

- **Keeping the 2022 codes as opaque identifiers.** It is what the code does today, and it would cost
  nothing. It also leaves every auditor to notice that `ART10` means Art. 13 and Annex I, and 1.0 would make
  that permanent.
- **Moving OWASP to 2025 before 1.0.** The rule sets in use do not carry 2025 tags, so coverage would drop
  to whatever a mapping guessed, and the weekly history would change meaning halfway through.
- **Codes without article numbers** (`CRA-NOTIF`). Stable under any renumbering, and useless to an auditor
  matching against the text.
