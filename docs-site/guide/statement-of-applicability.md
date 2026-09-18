# Statement of applicability

What your organisation **declares** about a control, set against what the estate **measures**.
The useful artefact is neither half on its own — it is the line where the two disagree.

ISO/IEC 27001 clause 6.1.3 d requires a statement of applicability: for every control, whether it
applies, whether it is implemented, and why an excluded one is excluded. Vectispire stores that
declaration and reconciles it, control by control, with what it can observe.

## Why the disagreement is the point

A control declared *implemented* that the estate measures *non-compliant* is exactly what an
assessor writes up. Neither half of the product could see it alone: the declaration is a document
nobody checks, the measurement is a number nobody claimed anything about.

The screen therefore sorts by **severity of divergence**, not by control identifier. The server
returns the rows in the standard's order, which is right for printing the document and wrong for
opening it — the question in front of this screen is "what is wrong", and it is answered at the
top.

| Divergence | What it means |
|---|---|
| **Contradicted** | Declared implemented, measured non-compliant. The organisation is not merely short of the control, it said otherwise in writing. |
| **Overstated** | Declared implemented, measured partial. A document ahead of the practice — a different class of problem from a false claim. |
| **Understated** | Declared planned, measured compliant. The document has drifted behind the practice. |
| **Undeclared** | Nobody addressed this control at all. |
| **Excluded without justification** | Clause 6.1.3 d allows an exclusion and requires it to be argued. |
| **Not measured here** | The evidence lives in another system; Vectispire declines to judge it. |

## A fresh instance shows findings, and that is correct

Clause 6.1.3 d requires *every* control to be addressed. Silence is the gap, so an empty document
reports one finding per control rather than a clean page. Sorting the undeclared to the bottom
would have made an empty document look like a finished one.

## Evidence that lives somewhere else

`evidence_source` is the field that stops this screen lying. Vectispire measures a slice of each
control — never the whole of it. A control whose evidence is an IAM access review or a supplier
questionnaire is shown as **not measured here**, which is a pointer to the other document and not
a finding against you.

A control evidenced *both* here and elsewhere is still judged, on the slice measured here.

## Lapsed reviews

A declaration carries a review date. The counter of overdue reviews opens onto the list, across
every framework — a number you cannot open is not a record of review, it is a reproach. A lapsed
review is counted separately from the divergence: the claim may still match the estate, and what
lapsed is the confirmation of it.

The screen opens on **ISO 27001**, not on the first framework in the list.

## Related

- [Compliance](compliance.md) — the measurement half, and the evidence bundle.
- [Certified scope](certified-scope.md) — what the controls apply to.
- [Exceptions](exceptions.md) — what was deliberately not fixed, and under what conditions.
