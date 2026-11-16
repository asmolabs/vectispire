# vectispire-cp-posture

The control plane's figures of risk in Rust — `core.posture` and the parts of `common.domain` it alone or first reads
(`scorecard`, `trends`, `remediation`, `attackpath`, `notifications.PostureDigest`), plan Phase 3, wave 1. Not shipped:
the Java control plane is the product. Its eighteen routes are served, composed in the binary and in the golden replay.

## What it does

| Rust | Java | |
|---|---|---|
| `scorecard` | `SecurityGrade`, `CandidateScore`, `SecurityScorecard`, `PortfolioScorecard`, `SvgBadgeGenerator` | the one formula of decision 0036 (`100 × exp(−risk points / k)`, held at one, capped at 54 by an exploited issue), the grades and the badge's SVG byte for byte |
| `coverage` | `SecurityScorecardService.Coverage`, `cappedToCoverage` | a score held at a scope's observed share, divided in `float` as Java divides it |
| `scorecards` | `SecurityScorecardService` | every card, the portfolio, each target's grade for the ranking and the simulation's counts — one computation, `card`, so one target reads one grade on every screen and on its badge |
| `badges` | `ScorecardBadgeService` | publishing is a decision: idempotent, audited once per change, served under a token, an unknown and a revoked token the same 404 |
| `simulation` | `ScoreSimulationService` | the production formula beside a candidate's over the caller's estate, its scopes graded both ways |
| `dashboard` | `DashboardQueryService`, `PostureScoreboards` | the home page (the gate's overview, never a figure of its own), the backlog's series and the posture analytics with the maturity ranking |
| `quality`, `debt`, `distribution` | `QualityQueryService`, `SecurityDebtService`, `RemediationDistributionService` | the quality screen, the debt estimate and its high-impact fixes, the remediation coverage and the distribution against the SLA |
| `attack_path`, `attack_paths` | `AttackPathService` and `common.domain.attackpath` | the graph drawn from a repository's endpoints and its worst open issues, cut at ten of each and scored on all |
| `trends` | `BacklogTrend`, `PostureTrendAnalytics` | the date arithmetic, in code rather than SQL, each comparison strict or not as Java's |
| `versions` | `common.domain.dependencies.Versions` | the highest fix version a finding announces |
| `digest`, `weekly`, `WeeklyDigestTask` | `PostureDigest`, `PostureDigestService`, `WeeklyDigestTask` | the weekly report, offered every hour (maintenance slot `WEEKLY_DIGEST`), sent at most once a week, audited after the send |
| `ports` | `NotificationService`, `MailNotificationChannel`, `OutboundPost` | **the weekly report's channels, behind `DigestChannels`** — see below |
| `routes` (`web`) | `DashboardController`, `QualityController`, `SecurityDebtController`, `AttackPathController`, `ScorecardController` | the eighteen routes |

**It owns no table**, so it has no `persistence` layer and no `.sqlx/` cache. Every figure is read through the module
that holds the rows, as Java's `allowedDependencies` say: the aggregates over `t_issue` are `cp-issues`'
(`persistence/aggregates.rs`, the backlog's own criteria under each), the completed scans and the recent history
`cp-scanning`'s, the names, badge tokens and project scopes `cp-targets'`, the licence violations and the endpoints
`cp-inventory`'s, the posture `cp-gate`'s overview.

## Authorization

Every route but the badge resolves the caller's `Visibility` (the account's grant intersected with the credential's).
A route naming a target — a repository's or an image's card, a repository's attack graph, its badge's state, its
publication and revocation — refuses a hidden one with **404**, never 403, in the service and **before the row is
read** (`rows::require_visible`), so no lookup tells a hidden target from an absent one: "Target not found." The
figures of the estate (dashboard, portfolio, quality, debt, distribution, overview of attack paths) are narrowed to
the allowance in the statement. The simulation is administrators' and still narrowed. The published badge is
anonymous, named by a 32-byte random token, never by the repository's id.

## The notifications port

The weekly report's channels are the notifications module's, which is not ported (wave 2). `DigestChannels` is the
port; `NotificationsStandIn` answers that **no destination is configured** — the absent answer — so the digest returns
before counting anything and writes no audit entry, exactly as a Java deployment that switched the report on and
configured no channel. No route reaches the digest, so no recording is affected; the stand-in is named in
`MIGRATION.md`, wave 2, where the notifications port plugs in its channels.

## Differences from Java

- **The licence term is counted from the inventory**, where Java reads per-target tallies it keeps in memory
  (`LicenseGovernanceService.violationsByTarget`). The tallies are, by their own contract, the inventory's count; the
  cost is a parse of the SBOMs in view per call. An untargeted scan's entries count in the total of a reader who sees
  everything, as in Java (2026-11-16, this port).
- **The attack graph's overview asks each repository's endpoints once**, where Java asks them for the page in one
  read. Same rows, more statements (2026-11-16, this port).

Fixed on the Java side rather than reproduced (2026-11-16, this port): `Map.of` and `Map.copyOf` sent the attack graph's
metadata and the digest's severities in an order salted per JVM start; the dashboard's and the digest's counts and the
analytics' MTTR were `HashMap`s; the digest formatted its mean with the default locale; and `CandidateScore` used
`Math.exp`, an intrinsic that may differ from fdlibm by an ulp from one platform to another — it is `StrictMath.exp`
now, and `arithmetic::strict_exp` is fdlibm's, checked bit for bit against the JDK on 200,019 arguments.

## Verification

- `tests/reference_set.rs` — `reference/posture/decisions.json`, written by `PostureReferenceSetTest`: the grades, the
  formula over a grid of backlogs and weights and the weights refused, the cap, the badge, the series, the analytics,
  the distribution and coverage, the versions and the weekly report's text.
- The unit tests in `scorecards`, `dashboard`, `debt`, `attack_path`, `arithmetic` and `web::read`.
- `tests/contract.rs` — the eighteen routes against `openapi.json`, the router probed.
- The golden replay (`cp-agents/tests/golden.rs`) on MySQL; `security/mutants/w1-posture.py`.
