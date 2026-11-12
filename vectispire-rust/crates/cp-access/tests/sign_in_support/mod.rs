//! The sign-in's collaborators in memory — the doubles `AuthServiceTest` builds with Mockito: one store for the
//! accounts, the attempts, the challenges, the second factor's columns and the rate windows; sessions that are minted
//! and remembered; an audit log that keeps its entries; a seal that binds a value to its context as the real one does,
//! so a wrong context reads as unreadable.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;
use vectispire_cp_access::accounts::{
    AccountStore, Audit, AuditRecord, NewUser, PasswordHash, RevokedKey, SessionHash, StoreError, User,
};
use vectispire_cp_access::credentials::{Clock, IssuedSession, SessionView, keys};
use vectispire_cp_access::passwords;
use vectispire_cp_access::rate_windows::RateWindowStore;
use vectispire_cp_access::second_factor::{Enrolled, SecretSeal};
use vectispire_cp_access::sign_in::{SessionDoor, SignInFlow, SignInMethodPolicy, SignInParts};
use vectispire_cp_access::throttle::{AttemptRow, SharedClock, SignInStore};
use vectispire_cp_crypto::EncryptionError;
use vectispire_domain::secret::Secret;

pub const NOW: OffsetDateTime = datetime!(2026-08-18 10:00:00 UTC);
pub const PASSWORD: &str = "correct horse battery staple";

/// A clock the test moves by hand.
#[derive(Debug)]
pub struct HandClock(Mutex<OffsetDateTime>);

impl HandClock {
    pub fn at(instant: OffsetDateTime) -> Arc<HandClock> {
        Arc::new(HandClock(Mutex::new(instant)))
    }

    pub fn advance(&self, by: time::Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for HandClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

/// Everything the store holds, and what was asked of it.
#[derive(Debug, Default)]
pub struct State {
    pub users: BTreeMap<i64, User>,
    /// A typed name the collation would resolve to an account, as `when(users.findByUsername("ÀLICE"))` stubs it.
    pub aliases: HashMap<String, i64>,
    pub lookups: Vec<String>,
    pub rehashed: Vec<i64>,
    pub attempts: Vec<(Uuid, String, OffsetDateTime)>,
    /// Every key a reservation wrote, in order.
    pub recorded: Vec<String>,
    pub cleared_keys: Vec<String>,
    pub deleted_id_batches: Vec<Vec<Uuid>>,
    pub challenges: BTreeMap<String, vectispire_cp_access::sign_in::Challenge>,
    pub swept_at: Vec<OffsetDateTime>,
    pub windows: BTreeMap<String, (i32, OffsetDateTime)>,
    /// When set, every statement fails.
    pub failing: bool,
    /// When set, `insert_first` fails once — another instance's insert won.
    pub lose_first_insert: bool,
    /// When set, `replace_backup_codes` finds the codes already replaced.
    pub backup_codes_raced: bool,
    /// A live-challenge count to answer instead of the real one.
    pub live_override: Option<u64>,
    /// The two enrolment counts to answer instead of the real ones — an account created between the two statements.
    pub counts_override: Option<(u64, u64)>,
}

/// The store, shared by clones.
#[derive(Clone, Debug, Default)]
pub struct Memory(pub Arc<Mutex<State>>);

fn failure() -> StoreError {
    StoreError("the store is down".into())
}

impl Memory {
    pub fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    pub fn add(&self, user: User) {
        self.state().users.insert(user.id, user);
    }

    pub fn user(&self, id: i64) -> User {
        self.state().users.get(&id).cloned().unwrap()
    }

    /// `n` failures under `key`, ten seconds before `at` — `fiveRecentAttempts()`.
    pub fn seed_attempts(&self, key: &str, n: usize, at: OffsetDateTime) {
        let mut state = self.state();
        for _ in 0..n {
            state.attempts.push((Uuid::new_v4(), key.to_owned(), at - time::Duration::seconds(10)));
        }
    }

    pub fn attempts_under(&self, key: &str) -> usize {
        self.state().attempts.iter().filter(|(_, k, _)| k == key).count()
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, State>, StoreError> {
        let state = self.state();
        if state.failing { Err(failure()) } else { Ok(state) }
    }
}

pub fn account(id: i64, username: &str, active: bool) -> User {
    User {
        id,
        username: username.to_owned(),
        email: None,
        password: Some(PasswordHash::new(passwords::hash(PASSWORD))),
        display_name: None,
        avatar_url: None,
        role: "USER".to_owned(),
        is_active: active,
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

impl AccountStore for Memory {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, StoreError> {
        Ok(self.guard()?.users.get(&id).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        let mut state = self.guard()?;
        state.lookups.push(username.to_owned());
        if let Some(id) = state.aliases.get(username).copied() {
            return Ok(state.users.get(&id).cloned());
        }
        Ok(state.users.values().find(|user| user.username == username).cloned())
    }

    async fn all_by_username(&self) -> Result<Vec<User>, StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }

    async fn insert(&self, _: NewUser) -> Result<User, StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }

    async fn save(&self, _: &User, _: bool) -> Result<(), StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }

    async fn save_revoking_everything(&self, _: &User) -> Result<Vec<RevokedKey>, StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }

    async fn change_own_password(
        &self,
        user_id: i64,
        hash: PasswordHash,
        _: OffsetDateTime,
        _: Option<SessionHash>,
    ) -> Result<Vec<RevokedKey>, StoreError> {
        let mut state = self.guard()?;
        if let Some(user) = state.users.get_mut(&user_id) {
            user.password = Some(hash);
        }
        Ok(Vec::new())
    }

    async fn rehash(&self, user_id: i64, hash: PasswordHash) -> Result<(), StoreError> {
        let mut state = self.guard()?;
        state.rehashed.push(user_id);
        if let Some(user) = state.users.get_mut(&user_id) {
            user.password = Some(hash);
        }
        Ok(())
    }

    async fn delete(&self, _: i64) -> Result<(), StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }

    async fn count_other_active_admins(&self, _: &[&str], _: i64) -> Result<u64, StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }

    async fn active_sessions_by_user(&self, _: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        Err(StoreError("not used by the sign-in".into()))
    }
}

impl SignInStore for Memory {
    async fn record_attempts(&self, keys: &[String], at: OffsetDateTime) -> Result<Vec<Uuid>, StoreError> {
        let mut state = self.guard()?;
        let mut ids = Vec::new();
        for key in keys {
            let id = Uuid::new_v4();
            state.attempts.push((id, key.clone(), at));
            state.recorded.push(key.clone());
            ids.push(id);
        }
        Ok(ids)
    }

    async fn attempts_after(&self, key: &str, after: OffsetDateTime) -> Result<Vec<AttemptRow>, StoreError> {
        Ok(self
            .guard()?
            .attempts
            .iter()
            .filter(|(_, k, at)| k == key && *at > after)
            .map(|(id, _, at)| AttemptRow { id: *id, occurred_at: *at })
            .collect())
    }

    async fn delete_attempts_by_key(&self, key: &str) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        state.cleared_keys.push(key.to_owned());
        let before = state.attempts.len();
        state.attempts.retain(|(_, k, _)| k != key);
        Ok((before - state.attempts.len()) as u64)
    }

    async fn delete_attempts(&self, ids: &[Uuid]) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        state.deleted_id_batches.push(ids.to_vec());
        let before = state.attempts.len();
        state.attempts.retain(|(id, _, _)| !ids.contains(id));
        Ok((before - state.attempts.len()) as u64)
    }

    async fn delete_attempts_before(&self, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        let before = state.attempts.len();
        state.attempts.retain(|(_, _, at)| *at >= cutoff);
        Ok((before - state.attempts.len()) as u64)
    }

    async fn find_challenge(
        &self,
        token_hash: &str,
    ) -> Result<Option<vectispire_cp_access::sign_in::Challenge>, StoreError> {
        Ok(self.guard()?.challenges.get(token_hash).cloned())
    }

    async fn insert_challenge(&self, challenge: &vectispire_cp_access::sign_in::Challenge) -> Result<(), StoreError> {
        self.guard()?.challenges.insert(challenge.token_hash.clone(), challenge.clone());
        Ok(())
    }

    async fn count_challenge_attempt(&self, token_hash: &str) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        Ok(match state.challenges.get_mut(token_hash) {
            Some(challenge) => {
                challenge.attempts += 1;
                1
            }
            None => 0,
        })
    }

    async fn discard_challenge(&self, token_hash: &str) -> Result<u64, StoreError> {
        Ok(u64::from(self.guard()?.challenges.remove(token_hash).is_some()))
    }

    async fn delete_expired_challenges(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        state.swept_at.push(now);
        let before = state.challenges.len();
        state.challenges.retain(|_, challenge| challenge.expires_at >= now);
        Ok((before - state.challenges.len()) as u64)
    }

    async fn count_live_challenges(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let state = self.guard()?;
        Ok(state
            .live_override
            .unwrap_or_else(|| state.challenges.values().filter(|c| c.expires_at > now).count() as u64))
    }

    async fn advance_totp_step(&self, user_id: i64, step: i64) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        let user = state.users.get_mut(&user_id).unwrap();
        if user.totp_last_step.is_none_or(|last| last < step) {
            user.totp_last_step = Some(step);
            Ok(1)
        } else {
            Ok(0)
        }
    }

    async fn replace_backup_codes(
        &self,
        user_id: i64,
        expected: &str,
        replacement: &str,
        at: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        if state.backup_codes_raced {
            return Ok(0);
        }
        let user = state.users.get_mut(&user_id).unwrap();
        if user.mfa_backup_codes.as_ref().map(|codes| codes.expose()) != Some(expected) {
            return Ok(0);
        }
        user.mfa_backup_codes = Some(vectispire_cp_access::accounts::Sealed::new(replacement));
        user.updated_at = at;
        Ok(1)
    }

    async fn enable_second_factor(&self, user_id: i64, enrolled: &Enrolled) -> Result<(), StoreError> {
        let mut state = self.guard()?;
        let user = state.users.get_mut(&user_id).unwrap();
        user.mfa_enabled = true;
        user.totp_secret = Some(vectispire_cp_access::accounts::Sealed::new(enrolled.totp_secret.clone()));
        user.mfa_backup_codes = Some(vectispire_cp_access::accounts::Sealed::new(enrolled.backup_codes.clone()));
        user.totp_last_step = Some(enrolled.last_step);
        user.updated_at = enrolled.at;
        Ok(())
    }

    async fn disable_second_factor(&self, user_id: i64, at: OffsetDateTime) -> Result<(), StoreError> {
        let mut state = self.guard()?;
        let user = state.users.get_mut(&user_id).unwrap();
        user.mfa_enabled = false;
        user.totp_secret = None;
        user.mfa_backup_codes = None;
        user.totp_last_step = None;
        user.updated_at = at;
        Ok(())
    }

    async fn count_active_with_password(&self) -> Result<u64, StoreError> {
        if let Some((accounts, _)) = self.guard()?.counts_override {
            return Ok(accounts);
        }
        Ok(self.guard()?.users.values().filter(|u| u.is_active && u.password.is_some()).count() as u64)
    }

    async fn count_active_with_password_and_no_second_factor(&self) -> Result<u64, StoreError> {
        if let Some((_, without)) = self.guard()?.counts_override {
            return Ok(without);
        }
        Ok(self.guard()?.users.values().filter(|u| u.is_active && u.password.is_some() && !u.mfa_enabled).count()
            as u64)
    }
}

impl RateWindowStore for Memory {
    async fn increment(&self, key: &str) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        Ok(match state.windows.get_mut(key) {
            Some((hits, _)) => {
                *hits += 1;
                1
            }
            None => 0,
        })
    }

    async fn insert_first(&self, key: &str, expires_at: OffsetDateTime) -> Result<(), StoreError> {
        let mut state = self.guard()?;
        if state.lose_first_insert {
            state.lose_first_insert = false;
            // Another instance inserted the row first; the primary key refuses this one.
            state.windows.insert(key.to_owned(), (1, expires_at));
            return Err(StoreError("duplicate key".into()));
        }
        if state.windows.contains_key(key) {
            return Err(StoreError("duplicate key".into()));
        }
        state.windows.insert(key.to_owned(), (1, expires_at));
        Ok(())
    }

    async fn hits_of(&self, key: &str) -> Result<Option<i32>, StoreError> {
        Ok(self.guard()?.windows.get(key).map(|(hits, _)| *hits))
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let mut state = self.guard()?;
        let before = state.windows.len();
        state.windows.retain(|_, (_, expires)| *expires >= now);
        Ok((before - state.windows.len()) as u64)
    }

    async fn delete_by_key_prefix(&self, pattern: &str) -> Result<u64, StoreError> {
        let prefix = pattern.trim_end_matches('%').to_owned();
        let mut state = self.guard()?;
        let before = state.windows.len();
        state.windows.retain(|key, _| !key.starts_with(&prefix));
        Ok((before - state.windows.len()) as u64)
    }
}

/// An audit log that keeps its entries.
#[derive(Clone, Debug, Default)]
pub struct Log(pub Arc<Mutex<Vec<AuditRecord>>>);

impl Log {
    pub fn entries(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
    }

    pub fn last(&self) -> AuditRecord {
        self.entries().last().cloned().expect("an entry")
    }
}

impl Audit for Log {
    async fn record(&self, record: AuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

/// A session opened, as the store would have held it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub user_id: i64,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// Sessions in memory.
#[derive(Clone, Debug, Default)]
pub struct Doors {
    pub opened: Arc<Mutex<Vec<Opened>>>,
    pub handoffs: Arc<Mutex<HashMap<String, SessionView>>>,
    pub revoked: Arc<Mutex<Vec<String>>>,
    pub failing_purge: bool,
}

fn view(hash: &str, user_id: i64, user_agent: Option<&str>, ip_address: Option<&str>) -> SessionView {
    SessionView {
        token_hash: hash.to_owned(),
        user_id,
        created_at: NOW,
        last_seen_at: NOW,
        expires_at: NOW + time::Duration::hours(12),
        user_agent: user_agent.map(str::to_owned),
        ip_address: ip_address.map(str::to_owned),
    }
}

impl Doors {
    pub fn opened(&self) -> Vec<Opened> {
        self.opened.lock().unwrap().clone()
    }

    /// A hand-off waiting under `token` for `user_id`.
    pub fn hand_off(&self, token: &str, user_id: i64) {
        self.handoffs.lock().unwrap().insert(token.to_owned(), view(&format!("handoff-{token}"), user_id, None, None));
    }
}

impl SessionDoor for Doors {
    async fn open(
        &self,
        user_id: i64,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<IssuedSession, StoreError> {
        let minted = keys::issue_session_token();
        self.opened.lock().unwrap().push(Opened {
            user_id,
            user_agent: user_agent.map(str::to_owned),
            ip_address: ip_address.map(str::to_owned),
        });
        Ok(IssuedSession { session: view(&minted.hash, user_id, user_agent, ip_address), token: minted.token })
    }

    async fn resolve_handoff(&self, token: &str) -> Result<Option<SessionView>, StoreError> {
        Ok(self.handoffs.lock().unwrap().get(token).cloned())
    }

    async fn exchange_once(&self, handoff: &SessionView) -> Result<Option<IssuedSession>, StoreError> {
        let consumed = {
            let mut handoffs = self.handoffs.lock().unwrap();
            let before = handoffs.len();
            handoffs.retain(|_, view| view.token_hash != handoff.token_hash);
            before != handoffs.len()
        };
        if !consumed {
            return Ok(None);
        }
        self.open(handoff.user_id, handoff.user_agent.as_deref(), handoff.ip_address.as_deref()).await.map(Some)
    }

    async fn revoke(&self, session: &SessionView) -> Result<(), StoreError> {
        self.revoked.lock().unwrap().push(session.token_hash.clone());
        self.handoffs.lock().unwrap().retain(|_, view| view.token_hash != session.token_hash);
        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, StoreError> {
        if self.failing_purge { Err(failure()) } else { Ok(2) }
    }
}

/// A seal that binds the value to its context: opened under any other context, it is unreadable — as AES-GCM with
/// the context as associated data is.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bound;

impl SecretSeal for Bound {
    async fn seal(&self, plain: &str, context: &str) -> Result<String, EncryptionError> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("sealed[{context}]{plain}"))
    }

    async fn open(&self, sealed: &str, context: &str) -> Option<Secret> {
        sealed.strip_prefix(&format!("sealed[{context}]")).map(Secret::new)
    }
}

pub type Flow = SignInFlow<Memory, Log, Memory, Doors, Bound>;

/// A flow over the doubles, password sign-in on and no provider.
pub fn flow(clock: SharedClock) -> (Flow, Memory, Log, Doors) {
    flow_with(clock, SignInMethodPolicy::new(false, true), None)
}

pub fn flow_with(
    clock: SharedClock,
    methods: SignInMethodPolicy,
    provider_label: Option<String>,
) -> (Flow, Memory, Log, Doors) {
    let (store, log, doors) = (Memory::default(), Log::default(), Doors::default());
    let flow = SignInFlow::new(SignInParts {
        users: store.clone(),
        audit: log.clone(),
        store: store.clone(),
        sessions: doors.clone(),
        seal: Bound,
        clock,
        methods,
        provider_label,
    });
    (flow, store, log, doors)
}
