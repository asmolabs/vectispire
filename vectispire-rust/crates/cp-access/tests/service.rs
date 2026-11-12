//! The account rules as the service applies them — `AccountAdministrationServiceTest`, the password half of
//! `AuthServiceTest` and `changePassword`'s, ported against an in-memory store that records every write, so that a
//! test can say which transaction ran and what it revoked.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;
use time::macros::datetime;
use vectispire_cp_access::accounts::{
    AccountChange, AccountError, AccountStore, Accounts, Audit, AuditOperation, AuditRecord, Clock, NewAccount,
    NewUser, PasswordAttempts, PasswordChange, PasswordHash, RequestActor, RevokedKey, SessionHash, StoreError,
    StoreOr, User,
};
use vectispire_cp_access::passwords;
use vectispire_domain::secret::Secret;

const NOW: OffsetDateTime = datetime!(2026-10-17 06:00:00 UTC);
const PASSWORD: &str = "an invented passphrase";

#[derive(Debug, Clone, PartialEq)]
enum Write {
    Insert(String),
    Save { id: i64, revoke_sessions: bool },
    SaveRevokingEverything(i64),
    ChangeOwnPassword { id: i64, keep: Option<String> },
    Rehash(i64),
    Delete(i64),
}

#[derive(Debug, Default)]
struct State {
    users: HashMap<i64, User>,
    next_id: i64,
    keys: HashMap<i64, Vec<RevokedKey>>,
    sessions: HashMap<i64, u64>,
    writes: Vec<Write>,
    lookups: Vec<String>,
    fail_rehash: bool,
}

#[derive(Debug, Clone, Default)]
struct Memory(Arc<Mutex<State>>);

impl Memory {
    fn with(&self, user: User) -> User {
        let mut state = self.0.lock().unwrap();
        state.next_id = state.next_id.max(user.id);
        state.users.insert(user.id, user.clone());
        user
    }
    fn writes(&self) -> Vec<Write> {
        self.0.lock().unwrap().writes.clone()
    }
    fn user(&self, id: i64) -> User {
        self.0.lock().unwrap().users[&id].clone()
    }
}

impl AccountStore for Memory {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, StoreError> {
        Ok(self.0.lock().unwrap().users.get(&id).cloned())
    }
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        let mut state = self.0.lock().unwrap();
        state.lookups.push(username.to_owned());
        Ok(state.users.values().find(|user| user.username == username).cloned())
    }
    async fn all_by_username(&self) -> Result<Vec<User>, StoreError> {
        let mut users: Vec<User> = self.0.lock().unwrap().users.values().cloned().collect();
        users.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(users)
    }
    async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
        let mut state = self.0.lock().unwrap();
        state.next_id += 1;
        let saved = User {
            id: state.next_id,
            username: user.username.clone(),
            email: user.email,
            password: user.password,
            display_name: user.display_name,
            avatar_url: None,
            role: user.role,
            is_active: user.is_active,
            github_id: None,
            keycloak_id: None,
            created_at: user.created_at,
            updated_at: user.created_at,
            must_change_password: user.must_change_password,
            mfa_enabled: false,
            totp_secret: None,
            mfa_backup_codes: None,
            totp_last_step: None,
        };
        state.users.insert(saved.id, saved.clone());
        state.writes.push(Write::Insert(user.username));
        Ok(saved)
    }
    async fn save(&self, user: &User, revoke_sessions: bool) -> Result<(), StoreError> {
        let mut state = self.0.lock().unwrap();
        state.users.insert(user.id, user.clone());
        if revoke_sessions {
            state.sessions.remove(&user.id);
        }
        state.writes.push(Write::Save { id: user.id, revoke_sessions });
        Ok(())
    }
    async fn save_revoking_everything(&self, user: &User) -> Result<Vec<RevokedKey>, StoreError> {
        let mut state = self.0.lock().unwrap();
        state.users.insert(user.id, user.clone());
        state.sessions.remove(&user.id);
        state.writes.push(Write::SaveRevokingEverything(user.id));
        Ok(state.keys.remove(&user.id).unwrap_or_default())
    }
    async fn change_own_password(
        &self,
        user_id: i64,
        hash: PasswordHash,
        at: OffsetDateTime,
        keep_session: Option<SessionHash>,
    ) -> Result<Vec<RevokedKey>, StoreError> {
        let mut state = self.0.lock().unwrap();
        let user = state.users.get_mut(&user_id).unwrap();
        user.password = Some(hash);
        user.must_change_password = false;
        user.updated_at = at;
        state.writes.push(Write::ChangeOwnPassword { id: user_id, keep: keep_session.map(|kept| kept.0) });
        Ok(state.keys.remove(&user_id).unwrap_or_default())
    }
    async fn rehash(&self, user_id: i64, hash: PasswordHash) -> Result<(), StoreError> {
        let mut state = self.0.lock().unwrap();
        if state.fail_rehash {
            return Err(StoreError("the database is read-only".into()));
        }
        state.users.get_mut(&user_id).unwrap().password = Some(hash);
        state.writes.push(Write::Rehash(user_id));
        Ok(())
    }
    async fn delete(&self, user_id: i64) -> Result<(), StoreError> {
        let mut state = self.0.lock().unwrap();
        state.users.remove(&user_id);
        state.writes.push(Write::Delete(user_id));
        Ok(())
    }
    async fn count_other_active_admins(&self, roles: &[&str], excluding: i64) -> Result<u64, StoreError> {
        assert_eq!(roles, ["SUPERUSER", "ADMIN"], "Role.administrative(), in declaration order");
        let state = self.0.lock().unwrap();
        Ok(state
            .users
            .values()
            .filter(|user| user.id != excluding && user.is_active && roles.contains(&user.role.as_str()))
            .count() as u64)
    }
    async fn active_sessions_by_user(&self, _at: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        Ok(self.0.lock().unwrap().sessions.clone())
    }
}

#[derive(Debug, Clone, Default)]
struct Log(Arc<Mutex<Vec<AuditRecord>>>);

impl Log {
    fn entries(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
    }
}

impl Audit for Log {
    async fn record(&self, record: AuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

#[derive(Debug, Clone, Copy)]
struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        NOW
    }
}

#[derive(Debug, Default)]
struct Budget {
    refused: Option<u64>,
    reserved: Mutex<Vec<i64>>,
    cleared: Mutex<Vec<i64>>,
}

impl PasswordAttempts for Budget {
    async fn reserve(&self, account_id: i64) -> Result<(), StoreOr<u64>> {
        self.reserved.lock().unwrap().push(account_id);
        match self.refused {
            Some(seconds) => Err(StoreOr::Refused(seconds)),
            None => Ok(()),
        }
    }
    async fn clear(&self, account_id: i64) -> Result<(), StoreError> {
        self.cleared.lock().unwrap().push(account_id);
        Ok(())
    }
}

fn account(id: i64, username: &str, role: &str) -> User {
    User {
        id,
        username: username.to_owned(),
        email: None,
        password: Some(PasswordHash::new(passwords::hash(PASSWORD))),
        display_name: None,
        avatar_url: None,
        role: role.to_owned(),
        is_active: true,
        github_id: None,
        keycloak_id: None,
        created_at: NOW,
        updated_at: NOW,
        must_change_password: false,
        mfa_enabled: false,
        totp_secret: None,
        mfa_backup_codes: None,
        totp_last_step: None,
    }
}

fn service() -> (Accounts<Memory, Log, Fixed>, Memory, Log) {
    let (store, log) = (Memory::default(), Log::default());
    (Accounts::new(store.clone(), log.clone(), Fixed), store, log)
}

fn actor() -> RequestActor {
    RequestActor { username: Some("root".to_owned()), ip_address: Some("192.0.2.1".to_owned()), user_agent: None }
}

fn invalid(result: Result<impl std::fmt::Debug, AccountError>) -> String {
    match result {
        Err(AccountError::InvalidInput(message)) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn secret(text: &str) -> Option<Secret> {
    Some(Secret::new(text))
}

// ── create ───────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_account_is_created_owing_a_password_change_with_its_role_upper_cased() {
    let (accounts, store, log) = service();
    let request = NewAccount {
        username: Some("  dana  ".to_owned()),
        password: secret(PASSWORD),
        role: Some(" ciso ".to_owned()),
        email: Some("  dana@example.org ".to_owned()),
        display_name: Some("   ".to_owned()),
    };
    let created = accounts.create(request, None, &actor()).await.unwrap();
    assert_eq!(created.user.username, "dana");
    assert_eq!(created.user.role, "CISO");
    assert!(created.user.must_change_password);
    assert_eq!(created.user.email.as_deref(), Some("dana@example.org"));
    assert_eq!(created.user.display_name, None);
    assert_eq!(created.active_sessions, 0);
    let stored = store.user(created.user.id);
    assert!(passwords::verify(Some(PASSWORD), stored.password.as_ref().map(PasswordHash::encoded)));
    let entry = &log.entries()[0];
    assert_eq!(entry.operation, AuditOperation::UserUpdated);
    assert_eq!(entry.description, "Account created: dana (CISO)");
    assert_eq!(entry.resource, created.user.id.to_string());
}

#[tokio::test]
async fn no_role_is_a_user() {
    let (accounts, _, _) = service();
    let created = accounts
        .create(
            NewAccount { username: Some("erin".to_owned()), password: secret(PASSWORD), ..NewAccount::default() },
            None,
            &actor(),
        )
        .await
        .unwrap();
    assert_eq!(created.user.role, "USER");
}

#[tokio::test]
async fn creation_refusals_say_what_java_says() {
    let (accounts, store, _) = service();
    store.with(account(1, "taken", "USER"));
    let create = |username: &str, password: &str, role: Option<&str>| NewAccount {
        username: Some(username.to_owned()),
        password: secret(password),
        role: role.map(str::to_owned),
        ..NewAccount::default()
    };
    assert_eq!(invalid(accounts.create(create("", PASSWORD, None), None, &actor()).await), "A username is required.");
    assert_eq!(
        invalid(accounts.create(create("a", PASSWORD, None), None, &actor()).await),
        "Invalid username: 2 to 64 characters, letters, digits, \". _ -\"."
    );
    assert_eq!(
        invalid(accounts.create(create("frank", "too short", None), None, &actor()).await),
        "The password must be at least 12 characters."
    );
    assert_eq!(
        invalid(accounts.create(create("frank", PASSWORD, Some("root")), None, &actor()).await),
        "Unknown role: ROOT."
    );
    assert_eq!(
        invalid(accounts.create(create("taken", PASSWORD, None), None, &actor()).await),
        "The username \"taken\" is already taken."
    );
    let long = NewAccount { email: Some("e".repeat(256)), ..create("frank", PASSWORD, None) };
    assert_eq!(
        invalid(accounts.create(long, None, &actor()).await),
        "The e-mail address is longer than 255 characters."
    );
    assert!(store.writes().is_empty(), "a refusal writes nothing");
}

#[tokio::test]
async fn only_a_governor_creates_a_governor() {
    let (accounts, store, _) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "governor", "SUPERUSER"));
    let request = || NewAccount {
        username: Some("second-governor".to_owned()),
        password: secret(PASSWORD),
        role: Some("SUPERUSER".to_owned()),
        ..NewAccount::default()
    };
    assert!(invalid(accounts.create(request(), Some(1), &actor()).await).starts_with("Only a platform governor"));
    assert!(invalid(accounts.create(request(), None, &actor()).await).starts_with("Only a platform governor"));
    assert!(accounts.create(request(), Some(2), &actor()).await.is_ok());
}

// ── update ───────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_reset_sets_the_flag_closes_the_sessions_and_takes_the_keys_each_audited() {
    let (accounts, store, log) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "gina", "USER"));
    let key = RevokedKey { id: uuid::Uuid::from_u128(7), name: "pipeline".to_owned() };
    store.0.lock().unwrap().keys.insert(2, vec![key.clone()]);
    store.0.lock().unwrap().sessions.insert(2, 3);
    let change = AccountChange { password: secret("a new invented passphrase"), ..AccountChange::default() };
    let updated = accounts.update(2, change, Some(1), &actor()).await.unwrap();
    assert_eq!(store.writes(), vec![Write::SaveRevokingEverything(2)]);
    assert!(updated.user.must_change_password);
    assert_eq!(updated.active_sessions, 0);
    assert!(passwords::verify(
        Some("a new invented passphrase"),
        store.user(2).password.as_ref().map(PasswordHash::encoded)
    ));
    let entries = log.entries();
    assert_eq!(entries[0].description, "Account gina: password reset, 1 API key revoked");
    assert_eq!(entries[1].operation, AuditOperation::ApiKeyDeleted);
    assert_eq!(entries[1].resource, "00000000-0000-0000-0000-000000000007");
    assert_eq!(entries[1].description, "API key revoked with its account's password reset: pipeline (account gina)");
}

#[tokio::test]
async fn a_role_change_or_a_deactivation_closes_the_sessions_and_nothing_else_keeps_them() {
    let (accounts, store, log) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "hal", "USER"));
    store.0.lock().unwrap().sessions.insert(2, 2);

    let unchanged = accounts.update(2, AccountChange::default(), Some(1), &actor()).await.unwrap();
    assert_eq!(unchanged.active_sessions, 2);
    assert!(log.entries().is_empty(), "nothing changed, nothing recorded");

    accounts
        .update(2, AccountChange { role: Some("ciso".to_owned()), ..AccountChange::default() }, Some(1), &actor())
        .await
        .unwrap();
    accounts
        .update(2, AccountChange { is_active: Some(false), ..AccountChange::default() }, Some(1), &actor())
        .await
        .unwrap();
    assert_eq!(
        store.writes(),
        vec![
            Write::Save { id: 2, revoke_sessions: false },
            Write::Save { id: 2, revoke_sessions: true },
            Write::Save { id: 2, revoke_sessions: true }
        ]
    );
    let descriptions: Vec<String> = log.entries().into_iter().map(|entry| entry.description).collect();
    assert_eq!(descriptions, ["Account hal: role USER → CISO", "Account hal: deactivated"]);
}

#[tokio::test]
async fn the_guard_rails_of_an_update() {
    let (accounts, store, _) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "governor", "SUPERUSER"));
    store.with(account(3, "ivy", "USER"));
    let role = |name: &str| AccountChange { role: Some(name.to_owned()), ..AccountChange::default() };

    assert_eq!(invalid(accounts.update(3, role("god"), Some(1), &actor()).await), "Unknown role: GOD.");
    assert_eq!(
        invalid(
            accounts
                .update(1, AccountChange { is_active: Some(false), ..AccountChange::default() }, Some(1), &actor())
                .await
        ),
        "You cannot deactivate your own account."
    );
    assert_eq!(
        invalid(accounts.update(1, role("USER"), Some(1), &actor()).await),
        "You cannot remove your own administrator role."
    );
    assert_eq!(
        invalid(accounts.update(3, role("ADMIN"), Some(3), &actor()).await),
        "You cannot change your own role: another administrator has to."
    );
    // Resetting a governor's password is administering it.
    let reset = AccountChange { password: secret("a new invented passphrase"), ..AccountChange::default() };
    assert!(invalid(accounts.update(2, reset, Some(1), &actor()).await).starts_with("Only a platform governor"));
    assert_eq!(
        invalid(
            accounts
                .update(3, AccountChange { password: secret("short"), ..AccountChange::default() }, Some(1), &actor())
                .await
        ),
        "The password must be at least 12 characters."
    );
    assert!(matches!(accounts.update(99, role("USER"), Some(1), &actor()).await, Err(AccountError::NotFound)));
    assert!(store.writes().is_empty());
}

#[tokio::test]
async fn the_last_active_administrator_stays_one() {
    let (accounts, store, _) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "governor", "SUPERUSER"));
    let mut lone = account(3, "lone", "ADMIN");
    lone.is_active = true;
    store.with(lone);
    // Two other active administrators: demoting one is fine.
    accounts
        .update(3, AccountChange { role: Some("USER".to_owned()), ..AccountChange::default() }, Some(2), &actor())
        .await
        .unwrap();
    // The governor demoting the last ADMIN still leaves the governor: SUPERUSER is administrative.
    accounts
        .update(1, AccountChange { role: Some("USER".to_owned()), ..AccountChange::default() }, Some(2), &actor())
        .await
        .unwrap();
    // Only a governor administers a governor, and nobody deletes themselves: a second governor, deactivated, asks.
    let mut other = account(4, "other-governor", "SUPERUSER");
    other.is_active = false;
    store.with(other);
    let message = invalid(accounts.delete(2, Some(4), &actor()).await);
    assert_eq!(
        message,
        "This is the last active administrator: deleting them would leave Vectispire with nobody able to administer it."
    );
}

// ── lifting the password-change requirement ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_lift_discards_the_local_password_closes_the_sessions_and_keeps_the_keys() {
    let (accounts, store, log) = service();
    store.with(account(1, "admin", "ADMIN"));
    let mut federated = account(2, "jo", "USER");
    federated.must_change_password = true;
    federated.keycloak_id = Some("subject-2".to_owned());
    store.with(federated);
    store.0.lock().unwrap().keys.insert(2, vec![RevokedKey { id: uuid::Uuid::from_u128(1), name: "kept".to_owned() }]);

    let lifted = accounts.clear_password_change_requirement(2, Some(1), &actor()).await.unwrap();
    assert!(!lifted.user.must_change_password);
    assert_eq!(store.writes(), vec![Write::Save { id: 2, revoke_sessions: true }]);
    let after = store.user(2);
    assert!(
        !passwords::verify(Some(PASSWORD), after.password.as_ref().map(PasswordHash::encoded)),
        "the old password is gone"
    );
    assert!(
        !passwords::needs_rehash(after.password.as_ref().map(PasswordHash::encoded)),
        "and replaced by a well-formed hash"
    );
    assert_eq!(store.0.lock().unwrap().keys[&2].len(), 1, "the keys stay");
    assert_eq!(
        log.entries()[0].description,
        "Account jo: password-change requirement lifted, local password discarded"
    );
}

#[tokio::test]
async fn the_lift_refuses_what_java_refuses() {
    let (accounts, store, log) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "user", "USER"));
    let mut by_password = account(3, "kim", "USER");
    by_password.must_change_password = true;
    store.with(by_password);
    let mut owes_nothing = account(4, "lee", "USER");
    owes_nothing.keycloak_id = Some("subject-4".to_owned());
    store.with(owes_nothing);
    let mut no_password = account(5, "max", "USER");
    no_password.must_change_password = true;
    no_password.password = None;
    store.with(no_password);

    assert!(matches!(
        accounts.clear_password_change_requirement(3, Some(2), &actor()).await,
        Err(AccountError::AccessDenied(message)) if message == "Only an administrator can lift another account's password-change requirement."
    ));
    assert!(matches!(
        accounts.clear_password_change_requirement(3, None, &actor()).await,
        Err(AccountError::AccessDenied(_))
    ));
    assert_eq!(
        invalid(accounts.clear_password_change_requirement(1, Some(1), &actor()).await),
        "You cannot lift your own password-change requirement: change your password."
    );
    assert!(
        invalid(accounts.clear_password_change_requirement(3, Some(1), &actor()).await)
            .starts_with("This account signs in with its password")
    );
    // Owes nothing: answered as it is, no write, no entry.
    accounts.clear_password_change_requirement(4, Some(1), &actor()).await.unwrap();
    assert!(store.writes().is_empty() && log.entries().is_empty());
    // No password at all: nothing to keep valid, and nothing is invented for it.
    accounts.clear_password_change_requirement(5, Some(1), &actor()).await.unwrap();
    assert_eq!(store.user(5).password, None);
}

// ── deletion ─────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn deletion_refuses_oneself_and_records_the_name() {
    let (accounts, store, log) = service();
    store.with(account(1, "admin", "ADMIN"));
    store.with(account(2, "nia", "USER"));
    assert_eq!(invalid(accounts.delete(1, Some(1), &actor()).await), "You cannot delete your own account.");
    accounts.delete(2, Some(1), &actor()).await.unwrap();
    assert_eq!(store.writes(), vec![Write::Delete(2)]);
    assert_eq!(log.entries()[0].description, "Account deleted: nia");
}

// ── one's own password ───────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_change_needs_the_current_password_even_when_one_is_owed() {
    let (accounts, store, log) = service();
    let mut owing = account(1, "olu", "ADMIN");
    owing.must_change_password = true;
    store.with(owing);
    let budget = Budget::default();
    let wrong = accounts
        .change_own_password(
            &budget,
            1,
            None,
            Some("not the password at all"),
            Some("a new invented passphrase"),
            Some("192.0.2.9"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(wrong, PasswordChange::CurrentPasswordWrong);
    assert!(budget.cleared.lock().unwrap().is_empty(), "a wrong password is a failure counted");
    let entry = &log.entries()[0];
    assert_eq!(entry.operation, AuditOperation::LoginFailure);
    assert_eq!(entry.description, "Password change refused: the current password was wrong");
    assert_eq!(entry.username.as_deref(), Some("olu"));
    assert_eq!(entry.ip_address.as_deref(), Some("192.0.2.9"));
    assert!(store.writes().is_empty());
}

#[tokio::test]
async fn a_change_spares_the_current_session_takes_the_keys_and_says_how_many() {
    let (accounts, store, log) = service();
    let mut owing = account(1, "pat", "USER");
    owing.must_change_password = true;
    store.with(owing);
    store.0.lock().unwrap().keys.insert(
        1,
        vec![
            RevokedKey { id: uuid::Uuid::from_u128(1), name: "one".to_owned() },
            RevokedKey { id: uuid::Uuid::from_u128(2), name: "two".to_owned() },
        ],
    );
    let budget = Budget::default();
    let changed = accounts
        .change_own_password(
            &budget,
            1,
            Some(SessionHash("kept".to_owned())),
            Some(PASSWORD),
            Some("a new invented passphrase"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(changed, PasswordChange::Changed { revoked_api_keys: 2 });
    assert_eq!(store.writes(), vec![Write::ChangeOwnPassword { id: 1, keep: Some("kept".to_owned()) }]);
    assert_eq!(*budget.cleared.lock().unwrap(), vec![1]);
    let user = store.user(1);
    assert!(!user.must_change_password);
    assert!(passwords::verify(Some("a new invented passphrase"), user.password.as_ref().map(PasswordHash::encoded)));
    let entries = log.entries();
    assert_eq!(entries[0].operation, AuditOperation::PasswordChanged);
    assert_eq!(entries[0].description, "Password changed by pat; 2 API keys revoked");
    assert_eq!(entries[1].description, "API key revoked with its account's password change: one (account pat)");
    assert_eq!(entries[2].resource, "00000000-0000-0000-0000-000000000002");
}

#[tokio::test]
async fn a_change_refuses_a_weak_or_unchanged_password_after_the_proof() {
    let (accounts, store, _) = service();
    store.with(account(1, "quin", "USER"));
    let budget = Budget::default();
    let weak = accounts.change_own_password(&budget, 1, None, Some(PASSWORD), Some("short"), None, None).await;
    assert_eq!(invalid(weak), "The password must be at least 12 characters.");
    let same = accounts.change_own_password(&budget, 1, None, Some(PASSWORD), Some(PASSWORD), None, None).await;
    assert_eq!(invalid(same), "The new password is the same as the old one.");
    assert_eq!(budget.cleared.lock().unwrap().len(), 2, "the proof was right both times");
    assert!(store.writes().is_empty());
}

#[tokio::test]
async fn a_throttled_change_is_recorded_as_a_blocked_sign_in() {
    let (accounts, store, log) = service();
    store.with(account(1, "rae", "USER"));
    let budget = Budget { refused: Some(42), ..Budget::default() };
    let answer = accounts
        .change_own_password(&budget, 1, None, Some(PASSWORD), Some("a new invented passphrase"), None, None)
        .await
        .unwrap();
    assert_eq!(answer, PasswordChange::Throttled { retry_after_seconds: 42 });
    let entry = &log.entries()[0];
    assert_eq!(entry.operation, AuditOperation::LoginBlocked);
    assert_eq!(entry.description, "Password change refused by the throttle (42s to wait)");
    assert_eq!(entry.signal, Some("SIGN_IN_THROTTLED"));
    assert!(store.writes().is_empty());
}

// ── the password half of the sign-in ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_sign_in_accepts_the_password_and_nothing_else() {
    let (accounts, store, _) = service();
    store.with(account(1, "sam", "USER"));
    let mut inactive = account(2, "tess", "USER");
    inactive.is_active = false;
    store.with(inactive);
    assert_eq!(
        accounts.check_sign_in_password(Some("sam"), Some(PASSWORD)).await.unwrap().map(|user| user.id),
        Some(1)
    );
    assert!(accounts.check_sign_in_password(Some("sam"), Some("not the password at all")).await.unwrap().is_none());
    assert!(accounts.check_sign_in_password(Some("nobody"), Some(PASSWORD)).await.unwrap().is_none());
    assert!(
        accounts.check_sign_in_password(Some("tess"), Some(PASSWORD)).await.unwrap().is_none(),
        "a deactivated account"
    );
    assert!(accounts.check_sign_in_password(Some("sam"), None).await.unwrap().is_none());
    assert!(store.writes().is_empty(), "today's hash is not rewritten");
}

#[tokio::test]
async fn a_name_no_account_can_hold_is_never_looked_up() {
    let (accounts, store, _) = service();
    store.with(account(1, "alice", "USER"));
    assert!(accounts.check_sign_in_password(Some("ali\u{AD}ce"), Some(PASSWORD)).await.unwrap().is_none());
    assert!(accounts.check_sign_in_password(None, Some(PASSWORD)).await.unwrap().is_none());
    assert!(store.0.lock().unwrap().lookups.is_empty());
}

#[tokio::test]
async fn a_weaker_hash_is_rewritten_on_success_and_a_failed_rewrite_is_not_fatal() {
    let (accounts, store, _) = service();
    let mut old = account(1, "uma", "USER");
    old.password = Some(PasswordHash::new(passwords::hash_with(PASSWORD, 4096, 1, 1).unwrap()));
    store.with(old.clone());
    assert!(accounts.check_sign_in_password(Some("uma"), Some(PASSWORD)).await.unwrap().is_some());
    assert_eq!(store.writes(), vec![Write::Rehash(1)]);
    let rewritten = store.user(1).password.unwrap();
    assert!(!passwords::needs_rehash(Some(rewritten.encoded())));
    assert!(passwords::verify(Some(PASSWORD), Some(rewritten.encoded())));

    store.with(old);
    store.0.lock().unwrap().fail_rehash = true;
    assert!(
        accounts.check_sign_in_password(Some("uma"), Some(PASSWORD)).await.unwrap().is_some(),
        "the sign-in still succeeds"
    );
}

#[tokio::test]
async fn an_active_account_without_a_password_is_refused_after_the_stand_in() {
    let (accounts, store, _) = service();
    let mut federated = account(1, "vic", "USER");
    federated.password = None;
    store.with(federated);
    assert!(accounts.check_sign_in_password(Some("vic"), Some("")).await.unwrap().is_none());
    assert!(accounts.check_sign_in_password(Some("vic"), Some(PASSWORD)).await.unwrap().is_none());
}

#[tokio::test]
async fn the_list_is_by_username_with_each_accounts_sessions() {
    let (accounts, store, _) = service();
    store.with(account(1, "zed", "USER"));
    store.with(account(2, "amy", "USER"));
    store.with(account(3, "max", "USER"));
    store.0.lock().unwrap().sessions.insert(3, 2);
    let every = accounts.list(None).await.unwrap();
    assert_eq!(every.total, 3);
    let names: Vec<&str> = every.accounts.iter().map(|view| view.user.username.as_str()).collect();
    assert_eq!(names, ["amy", "max", "zed"]);
    assert_eq!(every.accounts[1].active_sessions, 2);
    let page = accounts.list(Some((1, 1))).await.unwrap();
    assert_eq!((page.total, page.accounts.len(), page.accounts[0].user.username.as_str()), (3, 1, "max"));
}

#[test]
fn nothing_secret_prints() {
    let user = account(1, "wes", "USER");
    let printed = format!("{user:?} {:?}", SessionHash("deadbeef".to_owned()));
    assert!(!printed.contains("argon2id") && !printed.contains("deadbeef"), "{printed}");
    assert!(format!("{:?}", Secret::new(PASSWORD)).contains("***"));
}
