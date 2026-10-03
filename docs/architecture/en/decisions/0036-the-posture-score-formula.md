# 0036 — The posture score formula

**Date:** 2026-10-03 · **Status:** accepted · **Decider:** Laurent Boucher

*Accepted on 2026-10-03 by the product owner, on the simulation's tables below, with the two
questions the proposal left open settled: **a project and a solution are graded by their weakest
link**, the sum being rejected for its size effect, and **the portfolio has no single grade** — it
shows the distribution of its targets' grades, its weakest target and its total risk points. Nothing
of the switch was released when it was accepted; it ships in 0.11.0 (Rollout).*

## Context

A target's scorecard grade (A+ to F) is one number shown in five places: the repository and image
cards, the scope cards of projects and solutions, the dashboard's maturity ranking, and the public
SVG badge a team pastes into its README. Since the ranking stopped grading with weights of its own,
all five read one computation (`SecurityScorecardService.computeScorecard`):

```
score = clamp(0, 100, 100 − 25·KEV − 8·critical − 4·high − 5·disallowed licence + 5·[a completed scan])
```

KEV is charged on top of the severity; mediums and lows weigh nothing. The bands are those of
`SecurityGrade.fromScore`: 95 A+, 85 A, 70 B, 55 C, 40 D, below F.

**The scale saturates where the estates that most need telling apart sit.** Twenty-seven highs, or
four exploited criticals, already read 0, F — and so do two hundred highs, so a team that fixes a
hundred and seventy of them sees nothing move. At the other end, fifty and five hundred open mediums
both read 100, A+, because a medium weighs nothing. And the +5 for a completed scan lifts every
graded target by the same five points — a target is only graded once it has a completed scan
(decision [0007](0007-none-is-not-an-empty-list.md), `NO_DATA` otherwise) — so the bonus's only effect is
that a clean target's hundred absorbs a high, or a disallowed licence, without moving.

A candidate (`CandidateScore`, wired to no grade) and an administrators-only simulation route
(`GET /api/v1/scorecards/simulation`) were added on 2026-10-03 so that the replacement would be
decided on figures. The product owner validated a calibration the same day. On the seeded estates of
`ScoreSimulationRoutesTest` — the backlog item's complaints, plus licence estates — the two formulas
give (risk points: see the decision):

| Target (open, unsettled) | Current | Candidate | Risk points |
|---|---|---|---|
| clean | 100 A+ | 100 A+ | 0 |
| 1 critical | 97 A+ | 83 B | 10 |
| 1 exploited critical | 72 B | 54 D (capped from 63) | 25 |
| 50 mediums | 100 A+ | 63 C | 25 |
| 500 mediums | 100 A+ | 1 F | 250 |
| 27 highs | 0 F | 14 F | 108 |
| 4 exploited criticals | 0 F | 16 F | 100 |
| 2 critical, 6 high, 40 medium, 120 low | 65 C | 24 F | 79 |
| 1 disallowed licence | 100 A+ | 93 A | 4 |
| 1 critical, 1 disallowed licence | 92 A | 78 B | 14 |
| 10 disallowed licences | 55 C | 48 D | 40 |
| never scanned, 1 high | no data | no data | — |

| Grade | Current | Candidate |
|---|---|---|
| A+ | 5 | 1 |
| A | 1 | 1 |
| B | 1 | 2 |
| C | 2 | 1 |
| D | 0 | 2 |
| F | 2 | 4 |
| no data | 1 | 1 |

Eight of the eleven graded targets change grade, and every change is downwards. That is not an
accident of the sample: over a grid of 144,000 backlogs (0–4 exploited, 0–7 criticals, 0–29 highs,
mediums, lows, 0–14 licences) no grade rises; a *score* rises only inside F, where the current one
has already reached zero.

**Projects and solutions.** Since the rollout's first step the simulation lists every project and
solution the caller sees beside the targets: the current score its scope card gives against the
candidate over the scope's summed backlog, the coverage cap applied to both. On the scopes
`ScoreSimulationRoutesTest` seeds:

| Scope | Targets (observed) | Open | Licences, candidate (card) | Current | Candidate | Risk points |
|---|---|---|---|---|---|---|
| project with one clean repository | 1 (1) | — | 0 (0) | 100 A+ | 100 A+ | 0 |
| project with a repository and an image sharing a scan | 2 (2) | 1 high | 3 (6) | 71 B | 75 B | 16 |
| project of a critical-heavy and a medium-heavy repository | 2 (2) | 3 critical, 1 high, 60 medium, 20 low | 0 (0) | 77 B | 30 F | 66.5 |
| project with one of two repositories scanned, both clean | 2 (1) | — | 0 (0) | 50 D | 50 D | 0 |
| empty project | 0 | — | — | no data | no data | — |
| solution of the clean project and the critical/medium one | 3 (3) | as the latter | 0 (0) | 77 B | 30 F | 66.5 |

A scope sums its targets' backlogs, so it can read lower than every one of its targets — the
critical-heavy repository alone is 54 D, the medium-heavy one 55 C, the project holding both 30 F.
That is the formula doing what it is for: the two backlogs together are more exposure than either.

**The scope card counts some licences twice.** It sums its targets' inventories, and an image's
inventory holds the components and licence findings of every scan naming that image *and* a
repository — keyed to the repository, whose inventory holds them too. A project filing both targets
of such a scan charges those entries twice: three disallowed licences read six on the card above,
71 where 86 is due. Each target's own card counts them once, on the repository. The candidate counts
a scope's licences as its targets' cards do — the sum of their tallies, each entry on the one target
its scan is attributed to — and its issues once each however many of the scope's targets they name;
the simulation flags each scope whose card disagrees (`currentDoubleCounted`). With the card's six
the candidate would read 60 C rather than 75 B.

**How a scope aggregates its targets** (amended 2026-10-03). Summing the backlogs penalises size: the
two repositories above at 54 D and 55 C make a 30 F project, and a project of many reasonable targets
reads worse than any of them. The simulation therefore sets a second aggregation beside the sum in
every scope row — the **weakest link** (`weakestScore`, `weakestGrade`, `weakestTarget`): the scope's
score is the candidate score of its lowest-scoring observed target, exactly as that target's own row
reads it, and the row names that target (kind, id, name — one of the visible targets the same answer
lists, chosen among the scope's visible targets only). The coverage cap applies to the scope as it
does to the sum: the weakest observed target's score is held at the observed share. A scope with no
observed target is `NO_DATA`, and a target never scanned never competes, even when an import left
open issues on it — those still enter the sum's backlog and the risk points. The risk points stay the
sum's under both aggregations: each issue and each licence once, what is open in the scope, not how
it is graded. On the scopes of the table above:

| Scope | Targets (observed) | Current | Sum | Weakest link | Risk points | Weakest target |
|---|---|---|---|---|---|---|
| project with one clean repository | 1 (1) | 100 A+ | 100 A+ | 100 A+ | 0 | the clean repository |
| project with a repository and an image sharing a scan | 2 (2) | 71 B | 75 B | 75 B | 16 | the repository (1 high, 3 licences) |
| project of a critical-heavy and a medium-heavy repository | 2 (2) | 77 B | 30 F | 54 D | 66.5 | the critical-heavy repository |
| project with one of two repositories scanned, both clean | 2 (1) | 50 D | 50 D | 50 D (capped from 100) | 0 | the scanned repository |
| project whose only repository was never scanned, 1 high open | 1 (0) | no data | no data | no data | — | — |
| empty project | 0 | no data | no data | no data | — | — |
| solution of the clean project and the critical/medium one | 3 (3) | 77 B | 30 F | 54 D | 66.5 | the critical-heavy repository |

And on two projects seeded to show what the aggregation decides, each target a scanned repository:

| Scope | Targets (observed) | Current | Sum | Weakest link | Risk points | Weakest target |
|---|---|---|---|---|---|---|
| 20 repositories, 4 mediums each (each 96 A+) | 20 (20) | 100 A+ | 48 D | 96 A+ | 40 | the first of them |
| 10 clean repositories + 1 with an exploited critical | 11 (11) | 72 B | 54 D | 54 D | 25 | the exploited one |
| solution of both | 31 (31) | 72 B | 31 F | 54 D | 65 | the exploited one |

Under the sum the twenty-mediums project reads D for being twenty, where each of its targets reads
A+ and a project of one of them would too; under the weakest link it reads A+. Neither hides the
exploited critical behind the ten clean repositories: both read 54 D, the exploited cap.

## Decision

**The scorecard's score becomes the candidate's, with the validated calibration**, everywhere the
current one is read — one computation still, on every screen and on the badge.

```
risk points = 25·exploited + 10·critical + 4·high + 0.5·medium + 0.125·low + 4·disallowed licence
score       = max(1, round(100 × exp(−risk points / 55)))        capped at 54 if any issue is exploited
```

- **Each issue removes a share of what is left**, not a fixed number of points: the score falls
  quickly for the first issues and keeps falling without reaching the floor, so a backlog twice as
  large always scores lower. `k = 55` is the weighted backlog that brings the score to 100/e ≈ 37.
- **The calibration** (validated 2026-10-03): one critical reads B (83), one exploited critical D
  (the cap), fifty mediums C (63), one disallowed licence A (93). With a medium at 1 no `k` meets
  both of the first and third — B needs `k < 61.5`, C needs `k ≥ 83.6` — so the medium weighs 0.5,
  and the low a quarter of it.
- **Exploited is a class of its own, whatever the severity**, and an issue in it is counted under no
  severity. **Any exploited issue caps the grade at D** (score 54, D's top), which is what the
  grade's own description says D means: "unresolved critical vulnerabilities or KEV threats".
- **A disallowed licence weighs 4, a high's weight**, counted exactly as the card counts it today —
  the inventory's tally (`LicenseGovernanceService.violationsByTarget` for the ranking, the
  target's inventory for its card), never a second count. A scope's is the sum of its targets'
  tallies, each entry counted once (the double count above is fixed by the switch).
- **No bonus for a completed scan.** Having one is the condition for a grade at all; a target with
  none stays `NO_DATA` (decision 0007), decided before any score, exactly as now.
- **Held at 1, never 0**: zero reads "nothing left to lose", the saturation this replaces.
- **The risk points are shown to signed-in readers only** — beside the score on the target's card,
  on a project's and a solution's scorecard, and in the ranking, which orders by them once two
  targets share a score. Inside F the score stays at 1 while the risk points keep falling, so a team
  deep in F sees what it fixed. They are a sum of what is open and are stated as such, never as a
  percentage.
- **The public badge shows the letter, never the risk points** (amended 2026-10-03). The badge is
  anonymous and embedded in other people's READMEs: a letter says how a target is graded, the points
  would say how much is open on it and, render after render, how that moves — an attacker would learn
  when a backlog grows after a release and when a fix lands, and where to look first. The letter is
  coarse by design; the points stay behind a session, like every other figure of the backlog.
- **Unchanged**: the bands, what counts (open issues, settled triage — `not_affected`, `fixed` —
  left out), the coverage cap on a project's or a solution's score (the observed share), `NO_DATA`,
  and the recommendations.
- **A scope is graded by its weakest link** (accepted 2026-10-03). A project's or a solution's score
  is the lowest score among its observed targets, each computed as its own card computes it, held at
  the scope's observed share; `NO_DATA` when none is observed; the card names the target the grade
  comes from. A scope is no safer than its most exposed target, and its grade must not depend on its
  size: twenty targets of four mediums each are twenty A+ targets, not a D project. Its risk points
  are the sum of the scope's open backlog, each issue and licence once, so a large scope still shows
  how much is open. The sum is rejected (Alternatives rejected).
- **The portfolio has no single grade** (accepted 2026-10-03). The dashboard and
  `GET /api/v1/scorecards/global` state, over the targets the reader sees, **how many targets hold
  each grade** (`NO_DATA` among them, which is the coverage said outright), **the weakest target by
  name**, and **the total risk points** — each issue and licence once. A single grade over an estate
  helps nobody decide: computed over the summed backlog it is crushed by the estate's size — a few
  hundred reasonable targets read F however they move, the twenty-mediums project above at estate
  scale — and computed by the weakest link it is the worst target's grade under another name, which
  the weakest target's line already says with the target attached. The distribution is what a reader
  of an estate acts on: how many targets are in F, whether that number falls, and which one first.
  The portfolio's coverage cap goes with its grade; the `NO_DATA` count replaces it.

## Alternatives rejected

- **The linear formula with bigger caps** (or smaller charges per issue). It moves the saturation
  rather than removing it: any `100 − Σ` reaches zero at some backlog, and past it every target
  reads the same again. Charging mediums linearly enough to tell fifty from five hundred sends fifty
  mediums to F by themselves.
- **Normalising each component** (a sub-score per severity, per licence, averaged or weighted). It
  answers "how bad is each class" rather than "how exposed is this target", lets a clean class lift
  a target that is failing on another, and needs a reference per class (a "normal" number of
  highs) that nothing in an estate supplies. Every number on the card would then depend on a
  constant nobody can explain on the badge.
- **`k = 85`, medium 1.** It gives fifty mediums a C, but one critical then reads A (89) — a
  critical vulnerability on a card graded A is the very complaint the grade is meant to avoid.
  `k < 61.5` is needed for the critical's B; no single `k` serves both with a medium at 1.
- **A scope graded by the mean of its targets' scores**, plain or weighted by any size measure. It
  removes the size penalty, but a critical target hides behind clean ones: ten clean repositories
  and one holding an exploited critical average 96, A+, for a project whose exploited critical the
  sum and the weakest link both grade D. The grade would say the opposite of what the project holds.
- **A scope graded by the formula over its summed backlog** (the scope card's computation until
  0.11.0). It grades a scope by its size as much as by its exposure: twenty repositories of four
  mediums each, every one 96 A+, make a 48 D project; a 54 D repository and a 55 C one make a 30 F
  project; and the solution holding the twenty and the ten-plus-one projects reads 31 F where its
  weakest target reads 54 D. Splitting a project in two would raise both halves' grades with nothing
  fixed, and a team adding a clean repository to a project would lower it. The sum's one merit — a
  large scope shows how much is open — is kept by the risk points, which stay summed.
- **A single grade for the portfolio**, summed or weakest-link. Summed, the size effect above grows
  with the estate — forty targets with two highs each already sum to 320 risk points, a score of 1, F; weakest-link, it repeats the worst
  target's grade and hides how many others share it. Neither tells a reader what to do next; the
  distribution does.
- **Keeping the +5 bonus.** It is a constant for every graded target, so it changes nothing but
  the ceiling every target shares, and it hides one high or one licence on an otherwise clean card.

## Consequences

**Every grade moves, in one direction**: most targets read lower the day the formula changes
(the table above, and the grid). The change is visible to integrations, not only on screen:

| Consumer | What it reads | What it sees |
|---|---|---|
| Public badge, `GET /api/v1/scorecards/badges/{token}.svg`, embedded in other people's READMEs | the grade's letter and colour | a different letter and colour on the next render, with nobody having changed the repository — and still no figure: the risk points are not on it |
| `GET /api/v1/scorecards/repositories/{repoId}`, `…/containers/{containerId}` | `score`, `grade` | new values; a new `riskPoints` field |
| `GET /api/v1/scorecards/global` | `score`, `grade` and the rest of a target's card | **a different shape**: no `score` and no `grade` any more — a portfolio has none — but the count of targets per grade, the weakest target and the total risk points. An integration reading `score` or `grade` there reads nothing, which is the honest answer, rather than a figure that means something else |
| `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance` | the embedded `scorecard` | the weakest observed target's score, held at the coverage, and that target named; `riskPoints` over the scope's backlog; `licenseViolationCount` drops where a scan named one of the scope's images and one of its repositories |
| `GET /api/v1/dashboard/posture-analytics` | the maturity ranking's `securityScore`, `maturityGrade`, and its order | new values, a new order among ties broken by risk points |
| The interface: the scorecard component, the dashboard's ranking and portfolio, the project and solution pages | the fields above | the new figures and the risk points; the portfolio's distribution where its grade was |

**Nothing else reads the grade.** The gate decides on severities, KEV and its policy, never on the
grade or the score; no SIEM event, notification, ticket, export (SARIF, VEX, CSAF, CycloneDX) or the
shipped CI templates (`ci/gitlab/vectispire-gate.gitlab-ci.yml`) carries it. A consumer outside the
product that thresholds the badge's letter or the API's `score` — a dashboard of dashboards, a
"no worse than B" check in someone's pipeline — will see it drop, and nothing in Vectispire can
find such a consumer for us.

**Tests pin the current weights** (`SecurityScorecardDatabaseTest`, `ScorecardRoutesTest`,
`BadgeRoutesTest`, `TrendsRoutesTest`, `ProjectAggregatesRoutesTest`, the interface's fixtures) and
move with the switch; the user guide's "How the scorecard grade is computed" (en + fr) is rewritten with it.

**The constants become a contract.** Like a fingerprint's ingredients, a weight or `k` changed
later moves every badge overnight; any later change is a decision recorded here, not a setting.
That is also why the weights are not configurable per installation: two installations holding the
same estate grade it the same, as the SLA windows were kept out of the score for.

## Rollout

Decided with the product owner on 2026-10-03 (amendment):

1. **Before the switch**, the simulation route lists projects and solutions beside targets, so a
   scope's new grade is seen on the estate before it ships — done on 2026-10-03, the scope table
   above; the owner accepts this decision on that table. Each scope row carries both aggregations,
   the sum and the weakest link, since 2026-10-03 (amendment), so the choice between them is made on
   the same figures.
2. **One release switches it, 0.11.0**, everywhere at once: `computeScorecard` computes
   `CandidateScore`'s formula with `Weights.PROPOSED`, `SecurityScorecard` gains `riskPoints`, the
   ranking breaks ties on them, the badge keeps its letter alone, a scope is graded by its weakest
   link and the portfolio by its distribution. No flag and no period with two
   formulas live: two grades for one target on two screens is the defect the ranking's unification
   closed.
3. **The scope double count is fixed by the same switch**: a scope's licence term becomes the sum of
   its targets' tallies, as the candidate already computes it, and no entry is charged twice. Not
   before — a scope card that moved on its own one release ahead of the formula would be a second
   unexplained change.
4. **The release notes** carry it under **"Changes an integration can see"**: the formula, the
   tables above, the new `riskPoints` field (signed-in routes only), and the sentence a reader needs
   first — *grades drop because mediums, lows and every further issue now count, not because a
   project got worse; nothing in your repository changed*. How a scope is graded — its weakest
   target's grade —, the portfolio's new shape on `/scorecards/global`, and a scope's licence count
   falling are said there too.
5. **The dashboard's trend chart marks the switch** with a dated vertical line ("scorecard formula
   changed", 0.11.0), so that a reader comparing a period across it sees why the grades moved. The
   series it plots today are the backlog's, which the switch does not move; the line is for the reader
   who sets a grade beside them. Decided with the owner on 2026-10-03: the line goes on that chart and
   on **any series of the score added later**, from its first version. No chart of the score over time
   exists today — the ranking and the cards show the score as it stands — so nothing else carries it
   yet.
6. `CandidateScore` stops being a candidate (renamed into the scorecard's domain) and the simulation
   route is retired in the release after, once nobody needs the comparison.
