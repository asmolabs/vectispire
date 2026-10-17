# vectispire-cp-access

The control plane's `access` module, being ported (plan, Phase 1). **Not shipped; the Java control plane is the
product.** So far it holds **the credentials** (task 1.2): sessions, API keys, agents' keys and the SCIM token, and the
bearer filter's decisions behind `cp-http`'s `Credentials`.

## What is here

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

### Where the files are

The plan names `src/credentials/`; `cp-arch-tests`' layering rule names a module's places — root, `internal`,
`persistence`, `web` and its named interfaces — and refuses any other directory, and it keeps every query out of the
root and `internal`. So the credentials are split as a Java module is: `src/credentials.rs` is the API (re-exports),
`src/internal/credentials/` the rules and the service, `src/persistence/credentials/` every statement.

Every statement is `sqlx::query!` / `query_as!`, checked against both engines while compiling, from this crate's
offline cache `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh prepare` rewrites it, `check` proves it current). Each
engine's statements sit behind the features `mysql-queries` and `postgres-queries`, both on by default, as `cp-db`'s.

## Sessions and keys survive the switch

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

## Differences from Java, known

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

## Tests

`cargo test -p vectispire-cp-access` — Docker required, its absence fails the run. The cross-switch test pulls nothing
when the image is present locally; `VECTISPIRE_E2E_CONTROL_PLANE_IMAGE` names another (a locally built branch).
Containers and networks are `vs-rs-p1c-*`, removed on drop.
