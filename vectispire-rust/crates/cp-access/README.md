# vectispire-cp-access

The control plane's access module, `core.access` (plan, Phase 1). **Not shipped; the Java control plane is the
product.** What is here is task 1.1, accounts and passwords; sessions and keys (1.2), MFA and throttles (1.3),
single sign-on (1.4), authorization (1.5) and the audit log (1.6) plug into the traits it declares.

| Here | Java |
|---|---|
| `passwords` — Argon2id, the PHC string written and read by hand | `common.domain.crypto.PasswordHasher` |
| `account_rules` — `Role`, the username and password grammar, the lockout, governor, own-role and deletion rules, Java's `trim`, `length`, `toUpperCase(ROOT)` and `equalsIgnoreCase` | `common.domain.users.AccountRules`, `Role`, `BoundedText` |
| `accounts` — `UserView`, `Accounts` (create, update, lift, delete, list, change one's own password, the password half of the sign-in) and the ports `Audit`, `Clock`, `PasswordAttempts` | `AccountAdministrationService`, `AuthService.login` (lookup → rehash), `AuthenticationFlowService.changePassword` |
| `persistence` — `User`, `AccountStore`, `SqlAccountStore` on both engines, `SessionsAndKeys` | `UserEntity`, `UserRepository`, `AccountAdminService`'s transactions |

## Held to the Java side

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

## Differences, on purpose

- **No bcrypt.** The plan says old bcrypt hashes are recognised; the Java code does not recognise them, and neither
  does this.
- **The rehash writes the password column only.** Java saves the whole entity loaded at the sign-in, so a
  deactivation committed between that load and the rehash was written back as active.
- **A stored memory cost above 1 GiB is refused**, not allocated; **a parameter Java's `parseInt` reads as a
  non-ASCII digit is refused**; **`t=0` and `p=0` answer `false`** where Java throws. Each concerns only a row
  edited by hand.
- **The fixed statements are `sqlx::query`, not yet the checked `query!`**: that needs this crate's own offline
  cache and generation script (`cp-db`'s covers `cp-db` only). Every statement runs in `tests/engines.rs` on both
  engines meanwhile.

## Observed in the Java code while porting (not changed there)

- `changeOwnPassword` closes the other sessions only when the request came on a session: called with no current
  session, every session survives the change. The route is a session route today; ported as it is.
- `PasswordHasher.verify` lets BouncyCastle's `IllegalStateException` through for `t=0` or `p=0`.
