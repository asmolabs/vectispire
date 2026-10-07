# Risk analysis

Four views that answer "what does this actually put at risk", each from a different angle.

## EPSS
![EPSS prioritisation: two vulnerabilities ranked by exploitation probability, each with the action its tier calls for.](../assets/screens/en/epss.png)


The **EPSS** page ranks the estate by exploitation probability rather than by CVSS. Every
vulnerability carries its score, and the difference between the two numbers is the whole
point: CVSS says how bad it would be, EPSS says how likely anyone is to try.

CISA **KEV** status sits alongside it — not a prediction but a record that exploitation has
been observed. A KEV entry outranks a high EPSS, which outranks a high CVSS.

The KEV status comes from CISA's catalogue as the control plane last read it: every six hours, or
when a security lead presses **Synchronize** on the **Threat Intelligence** settings tab. That tab
says when it was last read, CISA's release date of the catalogue in use, and why the last attempt
failed if it did — a failure keeps the catalogue in use rather than emptying it. An open issue is
flagged when its CVE is listed and un-flagged when the catalogue stops listing it; a newly flagged
one is sent to the SIEM as `VECTI-SEC-002`. Before the first synchronisation nothing is flagged, and
the tab says *never synchronized* rather than a reassuring zero.

The EPSS scores come from FIRST's daily file as the control plane last read it: once a day, and
with the catalogue when a lead presses **Synchronize**. The same tab says which model produced the
scores in use and the day they are for, and why the last attempt failed if it did. A file is taken
only whole: one cut short, older than the one in use, or with a tenth fewer CVE is refused and the
scores in use are kept. Once a file is applied, the open issues' scores are refreshed from it —
which is what the ranking, the gate and the scorecards read. No scan asks FIRST anything, so which
CVE your repositories carry is never sent to a third party. Before the first synchronisation no CVE
has a score, and the ranking shows none rather than a measured zero.

The ranking covers open vulnerabilities whose triage is not settled: one triaged **not affected**
or **fixed** leaves it, as it leaves the gate and the scorecard. A dismissal still awaiting
approval stays ranked — a request is not a decision.

The ranking weighs CVSS, EPSS and KEV, and nothing else: the four quadrants of the matrix are
exactly the thresholds their captions state. There is no reachability term, card or column —
Vectispire runs no call-graph analysis, so it cannot say whether the vulnerable code is called.

## Attack paths

![An attack path: an unauthenticated route reaching a vulnerable component, reaching the data store — with the narrative the chain produces.](../assets/screens/en/attack-paths.png)

The attack path visualiser chains findings into routes rather than listing them
individually: an exposed component, a vulnerability that reaches it, a credential that was
committed near it. A route made of three medium findings can matter more than any one high
finding on the same target, and no severity-sorted list will ever show it.

A finding triaged **not affected** or **fixed** is no hop on a route: the screen's claim is that
something can be reached, and the team has already argued it cannot.

## Blast radius

Blast radius works from a component outwards: if this package is compromised, what does it
reach? Multi-tier dependency graphs are mapped across every registered repository and
image, so the answer covers the estate rather than one project.

Read it together with the [business criticality tier](repositories.md#business-criticality-tiers).
A wide blast radius that touches only Tier 3 internal tools is a different Monday than one
that touches a Tier 1 payment path.

## Attack surface and OWASP

**Attack surface** collects what is reachable from outside — the entry points a finding has
to traverse to matter.

**OWASP** groups the backlog by the OWASP categories, which is the vocabulary most
security reviews and most auditors already speak. It is a reframing of the same findings,
not a separate scan.

The current grid reads the whole estate you see, or **one solution or one project**, chosen above it —
the same picker as *By week*, kept in the address so a link shows the same view. Every figure is then
that scope's: a project never scanned reads *unmeasured* even where its neighbours are covered. A scope
you see only in part says so, and counts what you see. A count of open findings opens the backlog of
that category in the same scope, settled triage left out as the grid leaves it out.

### The Top 10, week by week

*OWASP report* → *By week* shows the same ten categories over 12, 26 or 52 weeks — or a range you
choose — for the whole estate or one project or solution. Each column is an ISO week, Monday to
Sunday in UTC; a column header selects the week, whose figures and grid appear below the heatmap.

- **A recorded week** is one the weekly record captured: its square has the grid's colour (findings,
  darker for more; nothing found; not measured; no scanner here), and its open count leaves settled
  triage out. **Accepted risks are shown apart**, in grey and in brackets — never added into open.
- **A reconstructed week**, before the record started, is **hatched**, and the curves are dashed over
  it. It is read from the issues' dates: there is no state for it, and its open count includes the
  issues triage had settled, because the triage of a past date is not known. That is why no change is
  shown for open across the week the record starts — the difference would be the definition changing.
- **Every count opens the backlog it counts**, in the same scope: an open count lists the issues of that
  category open at the end of the week's Sunday (and not settled, on a recorded week — triage as it
  stands today); an opened or resolved figure lists the issues first seen or resolved from its Monday to
  its Sunday; a reopened figure lists the issues brought back in that week. The backlog says what it was
  asked in a banner, with the way back and a way to clear it.
- **A total opens the issues placed in any of the ten categories** — never the whole backlog, whose
  licence and quality findings are in no category and would make the list longer than the bar. One
  exception: on a recorded week where a category was not measured, the total open count opens nothing,
  since the grid counted nothing in that category and the list would hold its issues.
- **Reopened** counts the issues a scan or an import found again after they were resolved — what makes
  open rise in a week with no opened bar to match. It is drawn in purple, stacked on the opened bar.
  Reopenings have been recorded only since the upgrade that introduced them: **a week that began
  before shows a dash, not a zero**, and a note under the view says from which week the figure exists.

*Export CSV* gives one row per week and category, with whether the week was reconstructed; *Print /
PDF* prints the view without the menus, through the browser's own "save as PDF". The address carries
the window, the scope and the selected week, so a link reproduces the view.

## Using these well

None of these views produce new findings. They re-rank the ones you have according to a
question severity cannot answer. Use them when the backlog is too long to work through in
order — which, on a real estate, is always.
