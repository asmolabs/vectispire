# vectispire-cp-access

The control plane's `access` module, `core.access`, being ported (plan, Phase 1). **Not shipped; the Java control
plane is the product.** So far it holds **accounts and passwords** (task 1.1); **the credentials** (task 1.2):
sessions, API keys, agents' keys and the SCIM token, and the bearer filter's decisions behind `cp-http`'s
`Credentials`; and **roles and their flags, what a caller may see, the row guards, four-eyes, and who could approve**
(task 1.5). MFA and throttles (1.3) and single sign-on (1.4) land beside these files.

## Accounts and passwords (task 1.1)

| Here | Java |
|---|---|
| `passwords` — Argon2id, the PHC string written and read by hand | `common.domain.crypto.PasswordHasher` |
| `account_rules` — the username and password grammar, the lockout, governor, own-role and deletion rules, Java's `trim`, `length`, `toUpperCase(ROOT)` and `equalsIgnoreCase` | `common.domain.users.AccountRules`, `BoundedText` |
| `accounts` — `UserView`, `Accounts` (create, update, lift, delete, list, change one's own password, the password half of the sign-in) and the ports `Audit`, `Clock`, `PasswordAttempts` | `AccountAdministrationService`, `AuthService.login` (lookup → rehash), `AuthenticationFlowService.changePassword` |
| `persistence` — `User`, `AccountStore`, `SqlAccountStore` on both engines, `SessionsAndKeys` | `UserEntity`, `UserRepository`, `AccountAdminService`'s transactions |

**The role is the chain's** (`vectispire_cp_http::principal::Role`, re-exported as `roles::Role` and from
`account_rules`): the rules read it and its flags (`roles::RoleFlags`) rather than a second enum of their own. The
name, `Role.of` and `Role.administrative()` the accounts need are on that one type.

### Held to the Java side

- **Hashes, both ways** (`tests/passwords.rs`, `AccountsReferenceSetTest`): every hash `PasswordHasher` made
  verifies here and says whether it needs a rehash as Java says; every hash this crate made verifies on the Java
  side. `reference/accounts/java-hashes.json` and `rust-hashes.json`.
- **`verify` on the edges** (`reference/accounts/verify.json`): 35 encodings — trailing `$`, padded base64, the
  URL-safe alphabet, reordered or repeated parameters, signs and leading zeros, short salts and digests,
  impossible parameters. Equal everywhere, except where BouncyCastle **throws** (`t=0`, `p=0`: an
  `IllegalStateException` that reaches the sign-in as a 500) — answered `false` here.
- **Every rule and message** (`reference/accounts/rules.json`): usernames, passwords (UTF-16 length), trimming,
  upper-casing and bounding, the six role flags, 32 lockout cases, 343 governor cases, 288 own-role cases
  (`equalsIgnoreCase` with `ǅ`/`ǆ`, `Σ`/`σ`, `straße`), the deletion grid.
- **Against the real Java control plane** (`tests/against_java.rs`, the published 0.11.0-rc.3 image on MySQL):
  Java's bootstrap account and an account created through `/api/v1/users` verify here; an account created here
  signs in and changes its password through Java; a Rust reset is the password Java accepts next; a weaker hash
  written here is rewritten by Java's sign-in and still verifies here; a lift done here discards the password Java
  would have accepted.
- **Both engines** (`tests/engines.rs`, MySQL 9.4 and PostgreSQL 17 migrated by `vectispire-migrate`): every
  statement, the transactions with the sessions they close, and a row written the way Hibernate writes it.

### Differences, on purpose

- **No bcrypt.** The plan says old bcrypt hashes are recognised; the Java code does not recognise them, and neither
  does this.
- **The rehash writes the password column only.** Java saves the whole entity loaded at the sign-in, so a
  deactivation committed between that load and the rehash was written back as active.
- **A stored memory cost above 1 GiB is refused**, not allocated; **a parameter Java's `parseInt` reads as a
  non-ASCII digit is refused**; **`t=0` and `p=0` answer `false`** where Java throws; **a memory below 8 × lanes is
  refused**, where BouncyCastle silently derives at 8 × lanes — `false` on both sides unless the digest was made at
  that raised cost, which `hash` never does. Each concerns only a row edited by hand.

### The checked statements

The statements are `sqlx::query!`, checked against both engines' migrated schema, as `cp-db`'s are: the answers live
in `crates/cp-access/.sqlx/`, both engines in one directory, each statement tagged with its engine.
`crates/cp-db/scripts/sqlx-prepare.sh prepare cp-access` rewrites the cache from throwaway servers migrated by the
real Flyway; `check` (a step of CI's `rust` job, over every crate with checked statements) fails when the committed cache differs from a regenerated one. Each engine's statements
are a feature (`mysql-queries`, `postgres-queries`), and cp-db is depended on without its own, so that a pass
describes one engine's statements against one database.

One statement is not checked: the count of the other active administrators on **MySQL**, whose `in (…)` holds one
placeholder per role the caller names. PostgreSQL's `= any($1)` is checked; MySQL has no array parameter, and the
spellings that would fake one compare under another collation than `in` does.

### Observed in the Java code while porting (not changed there)

- `changeOwnPassword` closes the other sessions only when the request came on a session: called with no current
  session, every session survives the change. The route is a session route today; ported as it is.
- `PasswordHasher.verify` lets BouncyCastle's `IllegalStateException` through for `t=0` or `p=0`.

## Credentials (task 1.2)

### What is here

| Rust | Java |
|---|---|
| `credentials::{state_of, should_record_activity, bearer_token, hash_of, handoff_hash_of, SessionPolicy}` | `common.domain.auth.Sessions` |
| `credentials::{normalize_scopes, normalize_lifetime, has_scope, restriction_of, scope_from_wire_name}`, `keys::generate` | `ApiKeys`, `ApiKeyScope`, `ApiKeyAuthService.hasScope` / `restrictionOf` |
| `credentials::phc` | `PasswordHasher` (Argon2id PHC; the accounts task 1.1 should take this rather than write a second reader) |
| `CredentialService::{resolve_session, authenticate_session, open_session, revoke, revoke_all_for_user, revoke_others, purge_expired, count_active_by_user}` | `AuthService` (its session half), `SessionCleanupService.pruneSessions`, `SessionRepository` |
| `CredentialService::{open_handoff, resolve_handoff, exchange_once}` | the single sign-on hand-off of `AuthService` |
| `CredentialService::{resolve_key, integration_for, authenticate_key, issue_integration_key, issue_agent_key, revoke_key, revoke_keys_owned_by}` | `ApiKeyAuthService`, `AgentKeys`, `ApiKeyAdministrationService.issue` / `revoke` |
| `CredentialService::scim_matches`, `impl Credentials for CredentialService` | `BearerAuthenticationFilter` |
| `Resolved::{principal, credential_restriction, actor}` | `VectispirePrincipal` |
| `AgentDirectory`, `IssuerSees` | the ports `agents` and the targets/visibility services answer |

#### Where the files are

The plan names `src/credentials/`; `cp-arch-tests`' layering rule names a module's places — root, `internal`,
`persistence`, `web` and its named interfaces — and refuses any other directory, and it keeps every query out of the
root and `internal`. So the credentials are split as a Java module is: `src/credentials.rs` is the API (re-exports),
`src/internal/credentials/` the rules and the service, `src/persistence/credentials/` every statement.

Every statement is `sqlx::query!` / `query_as!`, checked against both engines while compiling, from this crate's
offline cache `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh prepare` rewrites it, `check` proves it current). Each
engine's statements sit behind the features `mysql-queries` and `postgres-queries`, both on by default, as `cp-db`'s.

### Sessions and keys survive the switch

- **The stored forms are the same on both sides.** A session row's key is the SHA-256 (lower-case hex) of the token's
  UTF-8 bytes, a hand-off's the SHA-256 of `handoff:` and the token; an API key's hash is the Argon2id PHC string
  `PasswordHasher` writes, read the way `PasswordHasher.verify` reads it (Java's `split`, any order of `m=`/`t=`/`p=`,
  padding optional, the `v=` piece ignored, a 32-byte derivation compared in constant time).
- **`reference/credentials/`** holds what `CredentialsReferenceSetTest` (in `vectispire-common`) answers: token hashes,
  23 `Authorization` headers, 13 session states and activity grains, scope lists and lifetimes with the Java
  sentences, and 276 verdicts (32 of them acceptances) on PHC strings Java minted and varied. `tests/reference_set.rs` holds this crate to them.
- **`tests/across_the_switch.rs`** starts the published control plane (0.11.0-rc.3, by digest) on a throwaway MySQL
  8.4 and, on that same database: Java's session, Java's integration key and Java's agent key authenticate in Rust;
  a session Rust opened and a key Rust issued authenticate on Java, as a bearer token and as `X-API-Key`, and Java
  records the key's use; a revocation in Rust is a 401 on Java, Java's sign-out ends the session for Rust, and
  closing every session of the account in Rust closes Java's.
- **`tests/credentials_on_both_engines.rs`** runs every statement on MySQL 9.4 and PostgreSQL 17, migrated by
  `vectispire-migrate`.

### Differences from Java, known

- **The session header's scheme.** Java's session lookup takes only `Bearer <token>` exactly — `Bearer`, one space,
  a token without `\s`. `cp-http`'s bearer layer parses the header leniently (any case, any run of spaces) and hands
  this crate the token alone: the token's shape is checked here, the scheme's spelling cannot be. `bearer x` and
  `Bearer  x` therefore open a session in Rust and not in Java. **The fix is `cp-http`'s**: give the session lookup
  the strict parse (`credentials::bearer_token`), keep the lenient one for keys.
- **A store failure is "no credential" (401)**, logged at error level, where Java let the exception through (500).
  Neither tells the caller anything; failing closed is the half that matters.
- **The chain's `Principal` carries less than `VectispirePrincipal`**: no account id, session hash or key restriction.
  They are in `Resolved`, which the routes get from `authenticate_session` / `authenticate_key`; the routes task
  (1.7) should make the chain carry `Resolved` (or what it needs of it) in the request.
- **The audit actor.** `cp-http` names an integration key's calls by the account's name; Java names them
  `user (API key name)`. `Resolved::actor` is Java's (`VectispirePrincipal.attribution`, the 255-character cut
  included).
- **The SCIM token file** is read once at start by `cp-runtime`; Java re-reads `VECTISPIRE_SCIM_TOKEN_FILE` on every
  request, so a rotated file takes effect without a restart there and not here.
- **PHC edges no Java hash has**: parameters of zero, negative or written in non-ASCII digits, and salts under eight
  bytes, are refused here; BouncyCastle may accept some of them. `PasswordHasher` writes none.
- **A user agent cut at 255** keeps a surrogate pair whole, where Java's `substring` would leave half of one.
- **The anti-replay record** is a 0.12 change and not on this line; the agent protocol's sealing-key generation check
  is the agents module's.

### Tests

`cargo test -p vectispire-cp-access` — Docker required, its absence fails the run. The cross-switch test pulls nothing
when the image is present locally; `VECTISPIRE_E2E_CONTROL_PLANE_IMAGE` names another (a locally built branch).
Containers and networks are `vs-rs-p1c-*`, removed on drop.

## Roles, visibility, four-eyes (task 1.5)

| Java | here |
|---|---|
| `Role` and its six flags | `roles.rs` — the chain's `Role` (`vectispire-cp-http`), with the flags as a table with no default arm |
| the eight `@Requires*` markers | `vectispire_cp_http::Access` — held to the Java `@PreAuthorize` expressions by `tests/authz_reference_set.rs` |
| `VisibilityMode`, `VisibilityService`, `Allowance` | `visibility.rs`; the grants' statements in `persistence/grants.rs` |
| `ApiKeyAuthService.restrictionOf` | `visibility::restriction_of_key` |
| `RowVisibility`, `Visibilities.requireVisible` | `rows.rs` — one sentence per kind of row, 404 never 403 |
| `IssueDecisionService.canApprove`, `VexIngestorService.canApprove`, the approvers' refusal | `four_eyes.rs` |
| the four-eyes setting: `SettingsService.isEnabled(FOUR_EYES_APPROVAL_REQUIRED)`, and the three refusals of `SettingsAdministrationService.update` when it is switched on | `four_eyes::{required, switch_on_refusal}`, `TriageApprovers::refusal_to_switch_on` |
| `TriageApprovers` | `approvers.rs`; the count in `persistence/accounts.rs` |
| `VisibilityService.allowance(user, principal.credentialRestriction())` before a scoped handler | `security::CallerVisibility`, the chain's `VisibilityOf` |

The layout is the one `cp-arch-tests` holds a module to: the root files are the API and the services, `persistence`
holds every statement, `security` is the named interface `access::security`. A service names no query API — the
boundary test caught two such lines while this was written (a grant type in the root used by `persistence`, and
`sqlx::Error` in a service's error), and both moved.

**Every statement is checked** (`sqlx::query_as!`, `query_scalar!`), each engine's behind a feature as in `cp-db`,
and cached in `.sqlx/` beside this file; `crates/cp-db/scripts/sqlx-prepare.sh` prepares and checks this crate's
cache with the others' (`… check cp-access` for this one alone). None needed a query builder: the teams' grants are
one join rather than Java's two statements and its guard on an empty team list (an account in no team joins no row,
so `team_id in ()` has no statement left to occur in), and the approver count is one statement per role, summed,
rather than `role in (…)` built from the flags.

### What holds it to the Java code

- **`reference/access/`**, written by `vectispire-core`'s `AccessReferenceSetTest` and checked on every Java build: the
  roles and their flags, the markers' expressions, `VisibilityMode.of` over thirteen spellings, the key restrictions,
  four-eyes over every role, the four-eyes setting as read and as switched on (`four-eyes-switch.json`: ten stored
  spellings, then thirteen values × the eight answers `TriageApprovers` could give, through
  `SettingsAdministrationService.update` itself), `RowVisibility`'s guards over seven allowances against five projects, three solutions
  and five targets (98 cases), and **`VisibilityService` over 960 cases** — nine ways of being granted (direct, through
  teams, projects, overlaps, an unknown kind, an empty and an absent project) × seven roles (an unreadable one
  included) × three stored modes × five credential restrictions, plus no account. The Java service answers with its
  repositories fed from the matrix, as `VisibilityServiceTest` feeds them; the four-eyes methods are private and are
  called through reflection, so that the reference is the method and not a copy of its condition.
- **`tests/authz_reference_set.rs`** reads every file and requires the same answer, case by case — and the role model's
  agreements `RouteAuthorizationTest` and `AuthorizationCoverageTest` assert on the Java side: each marker is the
  flag it is named after, and the scope guards are the markers whose every role sees the whole estate. That last one
  found `cp-arch-tests`' `settles_scope` missing `PlatformGovernor`, which Java's derivation holds.
- **`tests/authz_on_both_engines.rs`** runs the 960 cases again on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`:
  the matrix's accounts, teams, grants, projects, targets and backlog as rows, the real service and its read-only
  transaction, then a real `VisibleSelect` on `t_issue` with the allowance it produced, compared with the backlog
  the Java side's row rule reads. Then a `.scoped()` route through the real chain hands the allowance to a handler's
  query, for a session, a narrowed key, an agent, the SCIM client and a lookup that fails (500, never an empty
  backlog); then `TriageApprovers` counts on the same rows, and refuses switching four-eyes on as they empty.
- **Mutations**: thirty-seven breaks of the guards, each caught by a red test, the sources restored byte for byte
  after the campaign. The SQL text is not mutated: a changed statement has no entry in the offline cache and does not
  compile, which is that guard.

### What the Java code answers that is worth knowing

- **Four-eyes has two answers for a caller with no readable role.** A decision taken by hand settles
  (`IssueDecisionService.canApprove`: `orElse(true)`), a VEX import queues (`VexIngestorService.canApprove`:
  `orElse(false)`) — though the second's comment says it applies the rule "exactly as IssueDecisionService". Both are
  ported as they are and pinned. An unreadable role passes no marker, so neither reaches a route today.
- **What switches four-eyes on is wider than what reads it as on.** The guards treat `TRUE`, `tRuE` and `1` as
  switching on (`isTruthy`), the type's validation then accepts only `true`, and `isEnabled` reads only `true`. So with
  no approver, `1` is refused in the four-eyes words; with approvers, in the validation's. Ported as it is: the
  refusal a caller sees decides which sentence the screen shows.
- **On MySQL, an account whose stored role is `admin` counts as an approver.** `TriageApprovers` compares `role`
  with `'ADMIN'` in SQL, and MySQL's default collation compares without case; PostgreSQL does not. `Role.of("admin")` is
  unreadable and authorizes nothing, so the settings screen can be told four-eyes is honourable by an approver who
  cannot approve. Same statement here, so the same answer per engine; `tests/authz_on_both_engines.rs` pins both.
- **`VisibilityMode.of` trims as `String.trim` does** — every character up to U+0020, the controls included, and no
  other: a no-break space before `everyone` reads as unreadable, hence `assigned`. `str::trim` would have opened it.

### Not done here

- The ports this crate defines are implemented elsewhere: `AccessSettings` by the settings store (1.6),
  `GrantableTargets` by the targets module, `PrincipalDirectory` by the credentials (1.2). The tests implement them
  over the database. Reading the four-eyes row and saving it are the settings module's; it asks `four_eyes::required`
  and `TriageApprovers::refusal_to_switch_on`, and checks the platform governor itself (`governorOnly` is per section).
- Granting — `TeamAdministrationService`, `AccountAdministrationService`'s assignments — and `TargetGrants` (the
  grantees of a project, revoking every grant and key of a deleted target) are administration and target deletion,
  not visibility: they come with those routes.
- A checklist's author exclusion under four-eyes is the checklists module's; only the role half is here.
