# vectispire-cp-access

The control plane's `access` module, `core.access`, being ported (plan, Phase 1). **Not shipped; the Java control
plane is the product.** So far it holds **accounts and passwords** (task 1.1); **the credentials** (task 1.2):
sessions, API keys, agents' keys and the SCIM token, and the bearer filter's decisions behind `cp-http`'s
`Credentials`; and **roles and their flags, what a caller may see, the row guards, four-eyes, and who could approve**
(task 1.5); **the second factor's codes and the sign-in throttle's arithmetic** (the pure half of 1.3); and **the sign-in
services** (1.3's service half): the throttle's reservations, the password sign-in, the second factor's challenge, TOTP
enrolment and recovery, the shared rate windows and the hourly cleanup; and **the administration services** (stage 2b,
what 1.7's routes call): an account's grants, teams, API keys, and the names other modules print; and **SCIM's
provisioning** (stage 2c): users, groups, their filters, pages and refusals. Single sign-on (1.4) and the routes (1.7)
land beside these files.

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

## The second factor and the sign-in throttle, pure (task 1.3, first half)

| Here | Java |
|---|---|
| `totp` — Base32 both ways, RFC 6238 over HMAC-SHA1, the matching step within ±1, the enrolment URI, secrets and backup codes | `common.domain.auth.Totp` |
| `login_throttle` — the two counters' decision, the sliding window, the user, account, second-factor and client keys | `common.domain.auth.LoginThrottle` |
| `vectispire_cp_http::address::client_bucket` | `common.domain.auth.ClientBuckets` |
| `vectispire_domain::team_rules` (in the domain: the targets module reads the kinds) | `common.domain.teams.TeamRules` |

They sit in this crate rather than in `crates/domain` because no other module uses them — the domain is linked by the
agent, and the user key's NFKD would have brought `unicode-normalization` into its graph — except `TeamRules`, whose
kinds the targets module names.

**Held to `reference/sign-in/` and `reference/teams/`** (`SignInReferenceSetTest`, `TeamRulesReferenceSetTest`, in
`vectispire-common`): `tests/sign_in_reference_set.rs` and `crates/domain/tests/teams_reference_set.rs`. An enrolled
authenticator must keep working across the switch, so the secret is decoded with Java's leniency (upper-cased by
`toUpperCase(ROOT)`, everything outside the alphabet dropped); a throttle key is a row the other control plane reads,
so the user key folds exactly as Java folds (the final sigma by `java::to_lower_root`).

### What porting found

- **`ClientBuckets` reads addresses as `InetAddress.ofLiteral` does, and `cp-http` did not.** `1.2.3` is `1.2.0.3`,
  `01.2.3.4` is `1.2.3.4`, `00001::` is an IPv6 group and `fe80::1%1` an address; `str::parse` refused each, so the
  same client counted against one budget on Java and another here. `client_bucket` now follows `IPAddressUtil`'s
  grammar, 108 addresses pinned. One difference stays: a scope naming an interface (`%eth0`) is refused here, where
  Java accepts it on a host that has that interface — an answer that depends on the machine, about a value no client
  address carries.
- **Two Java defects, fixed on the Java side first** (asmolabs/vectispire#74): `TeamRules.trimDescription` cut a
  surrogate pair in half at the 255th unit, and `/auth/mfa/enable` answered 500 for a secret with no Base32 letter in
  it (an empty HMAC key). The reference sets record the fixed behaviour; `totp`'s refusal of an empty key is pinned
  by a unit test, since HMAC here accepts the key `SecretKeySpec` refused.
- `LoginThrottle.decide(list, 0, now)` throws on Java (`orElseThrow` with nothing to wait for). No caller passes a
  limit under five; `decide_one` answers "allowed" instead, and the reference set does not include it.
- `JEẞICA` and `jeßica` fold to different keys (`jeßica`, `jessica`), though MySQL's collation equates them. It is no
  oracle: sign-in looks up only names matching `[A-Za-z0-9._-]{2,64}`, so no non-ASCII spelling opens an account.

## The sign-in services (task 1.3, second half)

| Here | Java |
|---|---|
| `throttle` — `Throttle`, `Reservation` (`reserve`, `release`, `reserve_second_factor`, `reserve_password`, `clear_password_failures`, `second_factor_lockout`, `clear_second_factor_failures`), and `PasswordAttempts` for `Accounts::change_own_password` | `AuthService`'s throttle half |
| `sign_in` — `SignInFlow::login` | `AuthService.login` |
| `sign_in` — `SignInFlow::{sign_in, verify, exchange, options, change_password}`, `SignInMethodPolicy` | `AuthenticationFlowService` (minus `completeFederatedSignIn`), `SignInMethodPolicy` |
| `second_factor` — `SecondFactor::{setup, enable, disable, verify, enrolment}`, the contexts (`cp-crypto`'s `totp_secret_context`, `backup_codes_context`) | `TotpService` |
| `rate_windows` — `RateWindows`, `impl SharedWindow` (`cp-http`), `shared_webhook_window` | `RateWindows` |
| `session_cleanup` — `SessionCleanup::prune`, `SessionCleanupTask` at `SESSION_CLEANUP`, `session_cleanup_task` | `SessionCleanupService`, `SessionCleanupTask` |
| `persistence/sign_in/` — `SignInStore`, `RateWindowStore`, `SqlSignInStore` | `LoginAttemptRepository`, `MfaChallengeRepository`, `RateWindowRepository`, `UserRepository`'s second-factor statements |

The services are written against ports — `AccountStore` (task 1.1), `SignInStore`, `RateWindowStore`, `SessionDoor`
(implemented by `CredentialService`), `SecretSeal` (implemented by `cp-crypto`'s `Encryption`) and `Audit` — so that
`AuthServiceTest`'s cases run over doubles (`tests/sign_in_flow.rs`) and the statements, the races and the Java tests
that need a database run on MySQL 9.4 and PostgreSQL 17 (`tests/sign_in_on_both_engines.rs`). `Accounts::
check_sign_in_password` is now three steps — `sign_in_lookup`, `verify_sign_in`, `rehash_if_stale` — which the login
calls with the throttle between the lookup and the derivation, so the account is looked up once.

**The binary composes two of them today**: `SESSION_CLEANUP` (its line left `cp-maintenance`'s `deferred.txt`) and the
webhook's shared window (`Chain::with_shared_webhook_window`, `crates/cp-app/src/main.rs`). The sign-in flows have no
route yet: they are composed with the routes (1.7).

### Held to the Java side

- **The throttle counts first, then checks**: each reservation commits its rows before counting the others', a refused
  one takes its rows back. On both engines, twelve reservations at once against a ceiling of five admit at most five,
  and twelve wrong passwords, twelve wrong current passwords, twelve wrong codes across four challenges and twelve
  attempts to switch the factor off each reach their check at most five times (`AuthenticationCeilingsTest`).
- **The statements that decide a race** are each raced on both engines: sixteen presentations of one challenge are
  sixteen counted, one TOTP step presented twice is accepted once, one backup code spent twice is spent once, and a
  window's first hit that loses its insert to another instance is counted (the interleaving forced, as
  `RateWindowsIntegrationTest` forces it); sixteen hits at once lose none and admit at most the ceiling.
- **A second factor crosses the switch** (`tests/across_the_switch.rs`, against the published 0.11.0-rc.3): enabled in
  Rust, Java asks for the code at sign-in, accepts the next one and disables the factor with a Rust backup code;
  enabled again on Java, Rust accepts its next code and spends one of its backup codes. The contexts are
  `TotpService`'s, `user:totp_secret:<id>` and `user:backup_codes:<id>`, and the codes are joined by `,`.
- **Every message and audit entry** is Java's, word for word: the throttle's `Attempt refused by the throttle (Ns to
  wait)` with `SIGN_IN_THROTTLED`, `Login failed`, the challenge destroyed after three codes and the account locked
  with `MFA_FAILURE_CEILING`, the backup code with `MFA_BACKUP_CODE_USED`, the enrolment's and disabling's sentences;
  every wait is `toSeconds()`, truncated.
- **Mutations**: `security/mutants/p1-7b-access-signin.py`, each guard broken once and caught by a red test.

### Differences, on purpose

- **Enabling and disabling the factor write the factor's columns only** (`mfa_enabled`, `totp_secret`,
  `mfa_backup_codes`, `totp_last_step`, `updated_at`). Java saves the whole entity read at the start of the request, so
  a role change or a deactivation committed in between was written back as it was — the same difference as the
  password's rehash.
- **An address absent from a login** is counted under `login:client:null`, as `String.valueOf(null)` is in Java; the
  routes always resolve one.
- **The single sign-on provider** is a configuration value handed in (`SignInParts::provider_label`, the default label
  `single sign-on`), not an OIDC client: that client is task 1.4's.

### Not here

- **The federated sign-in** (`AuthenticationFlowService.completeFederatedSignIn`, `ExternalIdentityService`,
  `FederatedSecondFactorPolicy`, the group sync) is task 1.4's, and so is the provider's label read from the client
  registration.
- **The routes** (`/api/v1/auth/**`, the 42 lines of `crates/cp-contract/reference/not-yet-ported/access.txt`) are task
  1.7's: they map `SignIn`, `Verification`, `Handoff` and `SecondFactorError` to their statuses and messages.

### A Java defect, fixed on both sides

**`AuthenticationFlowService.rememberChallenge` stored the user agent unclipped** into `t_mfa_challenge.user_agent`, a
`varchar(255)`, where a session's was clipped (`AuthService.clip`). A longer `User-Agent` failed the insert after the
password was accepted and its counters cleared: the published 0.11.0-rc.3 answers **500** to a sign-in with a
300-character agent from an account with a second factor. Fixed on the Java side first (asmolabs/vectispire#84, which
also cuts on a character boundary), and ported fixed: the challenge's agent is clipped as a session's is
(`a_user_agent_past_the_column_is_clipped_*`, a surrogate pair at the cut).

## The administration services (stage 2b)

What the users, teams and API keys routes of 1.7 will call. **No route here**: the 42 lines of
`crates/cp-contract/reference/not-yet-ported/access.txt` stay.

| Here | Java |
|---|---|
| `account_targets` — `AccountTargets::{targets, replace_targets}` | `AccountAdministrationService.targets` / `replaceTargets`, `AccountAdminService.replaceTargets` |
| `teams` — `TeamAdministration::{list, create, rename, delete, members, replace_members, targets, replace_targets, set_webhook}`, `TeamView`, the `WebhookPolicy` port (implemented by `cp-settings`' `Settings`) | `TeamAdministrationService` |
| `teams::TeamChannels` — `teams_granted`, `with_channel`, `any_team_has_one`, `webhook_url`, in the caller's transaction | `TeamChannels` |
| `api_key_administration` — `ApiKeyAdministration::{list, issue, key, names, revoke, targets}`, `KeyView`, `TargetOptions` | `ApiKeyAdministrationService` (the issuing itself stays `CredentialService::issue_integration_key`, task 1.2) |
| `account_names` — `AccountNames::{by_username, by_id}`, `display_name_of`, `AccountDirectory::{active, by_id}` | `AccountNames`, `AccountDirectory` |
| `internal/grant_targets` — `validate` | `internal/GrantTargets` |
| `administration` — `AdminError` (400, 400, 404, 422, failure) and the audit entry | the exceptions `ApiExceptionHandler` maps |
| `persistence/administration.rs` — `t_team`, `t_team_member`, `t_team_target`, `t_team_webhook`, `t_user_target`, and the reads of `t_user` the screens make; `persistence/credentials/api_keys.rs::all_newest_first` | `TeamRepository`, `TeamMemberRepository`, `TeamTargetRepository`, `TeamWebhookRepository`, `UserTargetRepository`, `ApiKeyRepository.findAllByOrderByCreatedAtDescIdDesc` |

**`GrantableTargets` carries Java's five questions** (`visibility.rs`): besides `targets_in`, `named` (in the order
given, `deleted target` for one that is gone), `project_exists`, `exists` and `labels`. `cp-targets`' `TargetsForAccess`
answers them from `naming` and its persistence, held by `cp-targets/tests/engines.rs`.

**Every statement is checked** (`sqlx::query!`, cached in `.sqlx/`) and runs on MySQL 9.4 and PostgreSQL 17 in
`tests/administration_on_both_engines.rs`, which also replays the Java tests that hold these services —
`GrantTargetsRoutesTest`, `TeamVisibilityTest` (the rows behind each route), `AccountInputRoutesTest`'s grant cases and
`ApiKeyIntegrationRoutesTest`'s issuing and refusals — with every sentence and audit entry word for word.
`GrantTargetsTest` is the unit test in `internal/grant_targets.rs`. Mutations: `security/mutants/p1-7c-access-admin.py`.

### Differences from Java, on purpose

- **One transaction per gesture.** `TeamAdministrationService` holds none, so a replacement's delete commits before its
  inserts and a team's deletion is four commits (reported below). Here each gesture commits together; the answer of a
  gesture that succeeds is the same.
- **Read in the primary key's order** where Java's repository has no `order by` (`findByTeamId`, `findByUserId`,
  `findAll`): a team's members by account id, its grants and an account's by kind then id — MySQL's clustered order,
  which the recordings show, and one PostgreSQL's heap does not promise.
- **One lookup per key or name.** `ApiKeyAdministration::names` and `AccountNames::by_username` look each distinct id or name
  up on its own, where Java binds a thousand per statement: the answer is the same (`by_username` through the
  sign-in's lookup, under the same collation), and every statement stays checked on both engines. The rows they serve —
  keys bound to SARIF sources, the people a document names — are few.
- **A team's channel is not sealed.** The task named a secret sealed under a Java context; there is none. Java stores
  `t_team_webhook.url` as typed — a webhook URL is `Sensitivity.SECRET` in the settings' sense (a capability, stored as
  written, never returned), not `ENCRYPTED` — and so does this: sealing it here would make every channel unreadable to
  the Java control plane on the same database.

### Java defects found while porting, fixed on both sides

Fixed on the Java side first (asmolabs/vectispire#87), and ported fixed:

- **`TeamAdministrationService.replaceTargets` kept repeats**: the same repository sent twice answered 200 with two
  entries and audited `Targets of …: 2` while one row was stored. De-duplicated now, as the account path is
  (`targets_are_replaced_wholesale`).
- **`TeamAdministrationService` had no transaction**: a failure between the delete and the inserts left a team with part
  of what the administrator submitted, and a deletion failing half-way a team without its members. Each gesture is one
  transaction on both sides (`TeamWriteAtomicityTest` on the Java side).

Not a defect after all: `replaceTargets` of a team has no null guard of its own, but its route turns a `null` body into
an empty list before calling it, so no request reaches it with one.

### Not here

- **`ScimProvisioningService`** is stage 2c, below.
- `BootstrapService`: no route of the 42 calls it (it runs at start); it comes with the binary's composition of access.
- The services are not composed by the binary yet: they are composed with their routes (1.7), as the sign-in flows.

## SCIM provisioning (stage 2c)

What the `/scim/v2/Users` and `/scim/v2/Groups` routes of 1.7 will call. **No route here**: they come with stage 3b, and
`crates/cp-contract/reference/not-yet-ported/access.txt` and `golden/deferred/access.txt` are unchanged.

| Here | Java |
|---|---|
| `scim` — `ScimProvisioning::{users, user, create_user, replace_user, patch_user, delete_user, groups, group, create_group, replace_group, patch_group, delete_group}`, `UserAttributes`, `PatchOperation`, `UserCreation`, `UserChange`, `GroupView`, `GroupCreation`, `GroupChange`, `ORIGIN_SCIM` | `ScimProvisioningService` |
| `scim::ScimError` — `InvalidInput` (400), `InvalidFilter` (400, `scimType` `invalidFilter`), `ProtectedAccount` (403), `Failed` (500) | `InvalidInputException`, `InvalidFilterException`, `ProtectedAccountException`, as `ScimUsersController`'s handlers answer them |
| `vectispire_domain::scim` — `Page` (1-based `startIndex`, `count` clamped to 500), `user_filter`, `member_ref`, `member_value_text`, `removal`, `INVALID_FILTER`, `UNIQUENESS`; `java::read_long` | `ScimProvisioningService.Page`, `SUPPORTED_FILTER` and `filterUsers`, `resolveUserId`, Jackson 3's `asString()`, `handleRemoveMembers`' path, `Long.parseLong` |
| `persistence/scim.rs` — the account columns a view carries, the reads by id (and locked, for a write), name and subject, the insert, the directory's columns, the sessions, the memberships with their usernames, the directory's upsert of a membership and the removal of one | `UserRepository`, `SessionRepository.deleteByUserId`, `TeamMemberRepository.findMembershipsOf` / `findAllMemberships` / `save` / `deleteById` |

**SCIM's groups are teams and its users accounts**: the teams' statements are the administration's (`team`,
`team_named`, `insert_team`, `update_team`, `delete_members`, …), the name rules `team_rules`' and `bounded_text`'s, the
roles and their flags `roles`'. A membership the directory sets is `scim` (`TeamMemberEntity.Origin.SCIM`), so the OIDC
claim's reconciliation leaves it alone.

### Held to the Java side

- **`reference/access/scim/`**, written by `vectispire-core`'s `ScimReferenceSetTest` from the service itself, its
  repositories mocked and recording what they are asked, and checked on every Java build: 82 filters — the lookup each
  made, or the controller's own 400 body (`status`, `scimType`, `detail`, the filter clipped at 200 units) — straddling
  `\s` (no Unicode space, `\x0B` yes), `.` (no line terminator after a backslash), `(?i)` (ASCII only: `uſerName` and the
  Kelvin sign are refused), the root locale's lower case (`ΣΑΣ`, `İ`, `ǅ`); 34 pages, `Integer.MIN_VALUE` to `MAX_VALUE`;
  55 PATCH member entries (`Long.parseLong`'s `+7`, `٧`, `７`, overflow, Jackson's `asString()` of numbers, booleans and
  `null`); 34 `remove` paths. `crates/domain/tests/scim_reference_set.rs` replays them.
- **`tests/scim_on_both_engines.rs`** runs every statement on MySQL 9.4 and PostgreSQL 17 and replays
  `ScimUsersRoutesTest`, `ScimGroupsRoutesTest`, `ScimPagingRoutesTest` and `ScimUsersControllerTest` case by case, every
  sentence and audit entry word for word (`resource` `SCIM`, attributed to the account's or the team's name, after the
  commit) — plus the bindings by flag (a champion by approving triage, an auditor by its scope, an unreadable role), the
  operator's `link-privileged-accounts`, and the transactions below.
- **Mutations**: `security/mutants/p1-7d-access-scim.py`.

### Differences from Java, on purpose

- **One transaction per gesture.** Java's group writes are one transaction already; its account writes are not — a
  replacement saves the row and then closes the sessions, a deletion closes the sessions and then deletes the row, each
  its own commit. Here an account's row and the sessions its change closes, and an account's deletion with its sessions,
  commit together; a group's deletion takes its members, grants and channel with it, as the team administration's does.
  The engine test proves it with a trigger, set as the server's administrator, refusing the second statement: nothing
  of the gesture is written, and nothing is recorded.
- **An account's write locks its row from the read** (`for update`): two replacements binding an unbound account to two
  subjects at once both passed Java's `bindOnce`, and the later write won — a rebinding the rule exists to refuse.
- **An account's write sets the directory's columns only** (`display_name`, `email`, `keycloak_id`, `is_active`, `role`,
  `updated_at`), where Java saves the whole entity read at the start: a second factor enrolled or a password changed in
  between was written back as it was read — the same difference as the rehash's and the second factor's.

### Java defects found while porting, fixed on both sides

Each confirmed through the controllers (a 500 with the correlation id, `ApiExceptionHandler`'s catch-all), fixed on the
Java side first (asmolabs/vectispire#92), and ported fixed:

- **An `externalId` another account is bound to answered 500**, on `POST /scim/v2/Users` and on a `PUT` binding an unbound
  account: `ScimProvisioningService.createUser` and `bindOnce` never asked, and the insert or update met
  `t_user.keycloak_id`'s unique constraint. On both sides now `UserCreation::ExternalIdTaken` / `UserChange::ExternalIdTaken`, for
  the routes to answer 409 `uniqueness` (RFC 7644 §3.3), with nothing written; asked under the constraint's own
  comparison (on MySQL, without case).
- **A PATCH member entry whose `value` is an object or an array answered 500**: `item.get("value").asString()` threw
  Jackson 3's `JsonNodeException` on a container (`handleAddMembers`, `replaceMembers`). Java reads it with
  `asString(null)` now, and such an entry names nobody on both sides, as an entry without a `value` does
  (`scim::member_value_text`); the reference set holds four of them.

### Observed in the Java code (not changed, ported as it is)

- **A PATCH `add` of somebody already in the team makes the row the directory's**: `members.save` merges the pairing and
  its origin becomes `scim`, where a `replace` keeps a listed member's row and origin. Ported as Java's merge does it (an
  upsert of the origin).
- **A user PATCH reads any operation**: `remove` with the path `active` and a boolean sets it, as `replace` does; only a
  deactivation is recorded.
- **A user PATCH's display name is not trimmed**, where a replacement's is (the controller trims it); neither are e-mail
  addresses or subjects.
- **A number past `u64` in a member's `value`**: Jackson keeps its digits, `serde_json` (without `arbitrary_precision`)
  reads a float; both name a username no account can hold. Not in the reference set; the routes (3b) decide the parser.

### Not here

- **The routes** (3b) — the DTOs (`ScimUserDto`, `ScimGroupDto`, `ScimListResponse`, `ScimErrorResponse`), the `Location`
  header, the `uniqueness` and not-found sentences (`ScimRefusal`), the reading of `roles[0]`, `emails[0]` and `name.formatted`
  into `UserAttributes` — and their composition in the binary.
