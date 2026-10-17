# vectispire-cp-access

The control plane's `access` module, as far as Phase 1 task 1.5 takes it: **roles and their flags, what a caller may
see, the row guards, four-eyes, and who could approve**. Accounts and passwords, sessions and keys, MFA and single
sign-on (tasks 1.1–1.4) land beside these files.

| Java | here |
|---|---|
| `Role` and its six flags | `roles.rs` — the chain's `Role` (`vectispire-cp-http`), with the flags as a table with no default arm |
| the eight `@Requires*` markers | `vectispire_cp_http::Access` — held to the Java `@PreAuthorize` expressions by `tests/reference_set.rs` |
| `VisibilityMode`, `VisibilityService`, `Allowance` | `visibility.rs`; the grants' statements in `persistence/grants.rs` |
| `ApiKeyAuthService.restrictionOf` | `visibility::restriction_of_key` |
| `RowVisibility`, `Visibilities.requireVisible` | `rows.rs` — one sentence per kind of row, 404 never 403 |
| `IssueDecisionService.canApprove`, `VexIngestorService.canApprove`, the approvers' refusal | `four_eyes.rs` |
| `TriageApprovers` | `approvers.rs`; the count in `persistence/accounts.rs` |
| `VisibilityService.allowance(user, principal.credentialRestriction())` before a scoped handler | `security::CallerVisibility`, the chain's `VisibilityOf` |

The layout is the one `cp-arch-tests` holds a module to: the root files are the API and the services, `persistence`
holds every statement, `security` is the named interface `access::security`. A service names no query API — the
boundary test caught two such lines while this was written (a grant type in the root used by `persistence`, and
`sqlx::Error` in a service's error), and both moved.

## What holds it to the Java code

- **`reference/access/`**, written by `vectispire-core`'s `AccessReferenceSetTest` and checked on every Java build: the
  roles and their flags, the markers' expressions, `VisibilityMode.of` over thirteen spellings, the key restrictions,
  four-eyes over every role, `RowVisibility`'s guards over seven allowances against five projects, three solutions
  and five targets (98 cases), and **`VisibilityService` over 960 cases** — nine ways of being granted (direct, through
  teams, projects, overlaps, an unknown kind, an empty and an absent project) × seven roles (an unreadable one
  included) × three stored modes × five credential restrictions, plus no account. The Java service answers with its
  repositories fed from the matrix, as `VisibilityServiceTest` feeds them; the four-eyes methods are private and are
  called through reflection, so that the reference is the method and not a copy of its condition.
- **`tests/reference_set.rs`** reads every file and requires the same answer, case by case — and the role model's
  agreements `RouteAuthorizationTest` and `AuthorizationCoverageTest` assert on the Java side: each marker is the
  flag it is named after, and the scope guards are the markers whose every role sees the whole estate. That last one
  found `cp-arch-tests`' `settles_scope` missing `PlatformGovernor`, which Java's derivation holds.
- **`tests/engines.rs`** runs the 960 cases again on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`:
  the matrix's accounts, teams, grants, projects, targets and backlog as rows, the real service and its read-only
  transaction, then a real `VisibleSelect` on `t_issue` with the allowance it produced, compared with the backlog
  the Java side's row rule reads. Then a `.scoped()` route through the real chain hands the allowance to a handler's
  query, for a session, a narrowed key, an agent, the SCIM client and a lookup that fails (500, never an empty
  backlog); then `TriageApprovers` counts on the same rows.
- **Mutations**: twenty breaks of the guards, nineteen caught. The one that survives — removing the guard on an empty
  team list — is safe because sea-query renders `team_id in ()` as `1 = 2`, which `persistence::grants` pins.

## What the Java code answers that is worth knowing

- **Four-eyes has two answers for a caller with no readable role.** A decision taken by hand settles
  (`IssueDecisionService.canApprove`: `orElse(true)`), a VEX import queues (`VexIngestorService.canApprove`:
  `orElse(false)`) — though the second's comment says it applies the rule "exactly as IssueDecisionService". Both are
  ported as they are and pinned. An unreadable role passes no marker, so neither reaches a route today.
- **On MySQL, an account whose stored role is `admin` counts as an approver.** `TriageApprovers` sends `role in
  ('ADMIN', …)`, and MySQL's default collation compares without case; PostgreSQL does not. `Role.of("admin")` is
  unreadable and authorizes nothing, so the settings screen can be told four-eyes is honourable by an approver who
  cannot approve. Same statement here, so the same answer per engine; `tests/engines.rs` pins both.
- **`VisibilityMode.of` trims as `String.trim` does** — every character up to U+0020, the controls included, and no
  other: a no-break space before `everyone` reads as unreadable, hence `assigned`. `str::trim` would have opened it.

## Not done here

- The ports this crate defines are implemented elsewhere: `AccessSettings` by the settings store (1.6),
  `GrantableTargets` by the targets module, `PrincipalDirectory` by the credentials (1.2). The tests implement them
  over the database.
- The statements are `sqlx::query` and sea-query, checked by running them on both engines, not `sqlx::query!`:
  `cp-db`'s cache script prepares one crate; making it prepare a module crate is the follow-up.
- A checklist's author exclusion under four-eyes is the checklists module's; only the role half is here.
