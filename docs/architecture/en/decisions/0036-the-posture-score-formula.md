# 0036 — The posture score formula

**Date:** 2026-10-03 · **Status:** proposed · **Decider:** Laurent Boucher

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
  target's inventory for its card), never a second count.
- **No bonus for a completed scan.** Having one is the condition for a grade at all; a target with
  none stays `NO_DATA` (decision 0007), decided before any score, exactly as now.
- **Held at 1, never 0**: zero reads "nothing left to lose", the saturation this replaces.
- **The risk points are shown** beside the score — on the card, on the badge (`F · 312 pts`, say)
  and in the ranking, which orders by them once two targets share a score. Inside F the score stays
  at 1 while the risk points keep falling, so a team deep in F sees what it fixed. They are a
  sum of what is open and are stated as such, never as a percentage.
- **Unchanged**: the bands, what counts (open issues, settled triage — `not_affected`, `fixed` —
  left out), the coverage cap on a project's, a solution's or the portfolio's score (the observed
  share), `NO_DATA`, and the recommendations. A scope's score applies the formula to the scope's
  summed backlog, as today's does; the simulation route shows targets only, so the rollout adds the
  scopes to it before the switch.

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
- **Keeping the +5 bonus.** It is a constant for every graded target, so it changes nothing but
  the ceiling every target shares, and it hides one high or one licence on an otherwise clean card.

## Consequences

**Every grade moves, in one direction**: most targets read lower the day the formula changes
(the table above, and the grid). The change is visible to integrations, not only on screen:

| Consumer | What it reads | What it sees |
|---|---|---|
| Public badge, `GET /api/v1/scorecards/badges/{token}.svg`, embedded in other people's READMEs | the grade's letter and colour | a different letter and colour on the next render, with nobody having changed the repository |
| `GET /api/v1/scorecards/repositories/{repoId}`, `…/containers/{containerId}`, `…/global` | `score`, `grade` | new values; a new `riskPoints` field |
| `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance` | the embedded `scorecard` | as above, over the scope's backlog and coverage |
| `GET /api/v1/dashboard/posture-analytics` | the maturity ranking's `securityScore`, `maturityGrade`, and its order | new values, a new order among ties broken by risk points |
| The interface: the scorecard component, the dashboard's ranking, the project and solution pages | the fields above | the new figures and the risk points |

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

1. **Before the switch**, the simulation route lists projects and solutions beside targets, so a
   scope's new grade is seen on the estate before it ships.
2. **One release switches it**, everywhere at once: `computeScorecard` computes `CandidateScore`'s
   formula with `Weights.PROPOSED`, `SecurityScorecard` gains `riskPoints`, the badge prints them, the
   ranking breaks ties on them. No flag and no period with two formulas live: two grades for one
   target on two screens is the defect the ranking's unification closed.
3. **The release notes** carry it under **"Changes an integration can see"**: the formula, the
   table above, "every grade may drop — nothing in your repository changed", the new `riskPoints`
   field, and the badge's new text.
4. `CandidateScore` stops being a candidate (renamed into the scorecard's domain) and the simulation
   route is retired in the release after, once nobody needs the comparison.
