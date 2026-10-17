//! Sessions and credentials — `AuthService`'s session half, `ApiKeyAuthService`, `AgentKeys`, the key half of
//! `ApiKeyAdministrationService`, and the bearer filter's decisions, behind `cp-http`'s [`Credentials`].
//!
//! The rules themselves are in [`sessions`], [`api_keys`] and [`phc`]; this file is what reads and writes the store
//! for them, in the order the Java services do it, because the order is part of the behaviour: a session is checked
//! for its lifetime before its account, an expired key is refused **before** its last use is recorded, and a key
//! with the `agent` scope is an agent's or nobody's — never an integration's.

pub(crate) mod api_keys;
pub(crate) mod phc;
pub(crate) mod sessions;
pub(crate) mod text;

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_http::credentials::{BoxFuture, Credentials, secret_equals};
use vectispire_cp_http::principal::Account;
use vectispire_cp_http::{ApiKeyScope, Principal, Role};
use vectispire_domain::secret::Secret;

pub use crate::persistence::credentials::StoreError;
use crate::persistence::credentials::accounts::{self, AccountRow};
use crate::persistence::credentials::api_keys::{self as key_store, KeyRow};
use crate::persistence::credentials::sessions::{self as session_store, SessionRow};

use self::api_keys::IssueRefusal;
use self::sessions::{HANDOFF_LIFETIME, SessionPolicy};
use self::text::{clip_utf16, java_trim};

/// The instant a credential is judged at — `CoreConfiguration.clock()`, microseconds in UTC.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

/// The wall clock, truncated to the microsecond both engines keep: an instant written at nanoseconds and read back
/// would disagree with itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc();
        let nanos = now.nanosecond();
        now.replace_nanosecond(nanos.saturating_sub(nanos % 1_000)).unwrap_or(now)
    }
}

/// The agent a key belongs to — `AgentDirectory`, the port the agents module implements on its own table.
pub trait AgentDirectory: Send + Sync + std::fmt::Debug {
    fn by_api_key<'a>(&'a self, key_id: Uuid) -> BoxFuture<'a, Result<Option<AgentRef>, StoreError>>;
}

/// An agent, as far as a credential needs to know it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRef {
    pub id: Uuid,
    pub name: String,
}

/// Whether a key's issuer may restrict it to a target: it exists and the issuer's account sees it
/// (`ApiKeyAdministrationService.requireIssuerSees`). The targets and visibility tasks answer it.
pub trait IssuerSees: Send + Sync {
    fn issuer_sees<'a>(&'a self, issuer: i64, target: ScanTarget) -> BoxFuture<'a, Result<bool, StoreError>>;
}

/// `vectispire.scim.*`: the identity provider's provisioning token, and whether SCIM is on.
#[derive(Clone, Debug, Default)]
pub struct ScimToken {
    pub enabled: bool,
    pub token: Option<Secret>,
}

/// A session as the layers above hold it — the row's properties; never the token, which the store does not hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionView {
    /// Identifies the session: to revoke it, or to spare it when the account's other sessions are closed.
    pub token_hash: String,
    pub user_id: i64,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

impl From<SessionRow> for SessionView {
    fn from(row: SessionRow) -> SessionView {
        SessionView {
            token_hash: row.token_hash,
            user_id: row.user_id,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
            user_agent: row.user_agent,
            ip_address: row.ip_address,
        }
    }
}

/// A session just opened: the row, and the token the client must be given — which exists nowhere else.
#[derive(Debug)]
pub struct IssuedSession {
    pub session: SessionView,
    pub token: Secret,
}

/// An account that may still act, as a credential carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountView {
    pub id: i64,
    pub username: String,
    /// `None` when the stored role is unreadable: such an account is authorized for nothing.
    pub role: Option<Role>,
    pub must_change_password: bool,
}

impl AccountView {
    fn of(row: AccountRow) -> AccountView {
        AccountView {
            id: row.id,
            role: Role::parse(&row.role),
            username: row.username,
            must_change_password: row.must_change_password,
        }
    }

    fn account(&self) -> Account {
        Account { username: self.username.clone(), role: self.role, must_change_password: self.must_change_password }
    }
}

/// A key that authenticated — `ApiKeyView`, without its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyView {
    pub id: Uuid,
    pub name: String,
    pub prefix: Option<String>,
    pub scopes: String,
    pub target_kind: Option<String>,
    pub target_id: Option<i64>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub owner_user_id: Option<i64>,
}

impl From<KeyRow> for KeyView {
    fn from(row: KeyRow) -> KeyView {
        KeyView {
            id: row.id,
            name: row.name,
            prefix: row.prefix,
            scopes: row.scopes,
            target_kind: row.target_kind,
            target_id: row.target_id,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            expires_at: row.expires_at,
            owner_user_id: row.owner_user_id,
        }
    }
}

impl KeyView {
    pub fn has_scope(&self, scope: ApiKeyScope) -> bool {
        api_keys::has_scope(Some(&self.scopes), scope)
    }

    /// `isExpired`, as the administration screen shows it.
    pub fn is_expired(&self, as_of: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|expires| expires <= as_of)
    }
}

/// What an integration key stands for (decision 0024): the account it acts for — whose role and visibility apply —
/// narrowed by the key's own restriction, which every route intersects with the account's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Integration {
    pub owner: AccountView,
    pub key_id: Uuid,
    pub key_name: String,
    pub scopes: Vec<ApiKeyScope>,
    pub restriction: Visibility,
}

/// Who a bearer credential is, with what the routes need beyond the chain's [`Principal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    Session {
        account: AccountView,
        session: SessionView,
    },
    Integration(Integration),
    /// An agent's key: the protocol reads no visibility, and an agent's key is issued unrestricted.
    Agent {
        agent: AgentRef,
        key_id: Uuid,
    },
    /// The SCIM client: an administrator on `/scim` and nowhere else.
    Scim,
}

impl Resolved {
    /// The principal the chain reads.
    pub fn principal(&self) -> Principal {
        match self {
            Resolved::Session { account, .. } => Principal::session(account.account()),
            Resolved::Integration(integration) => Principal::integration(
                integration.owner.account(),
                &integration.key_id.as_hyphenated().to_string(),
                integration.scopes.clone(),
            ),
            // `VectispirePrincipal.getName()` of an agent, which is what the audit entries it causes name.
            Resolved::Agent { agent, .. } => Principal::agent(&format!("agent:{}", agent.name)),
            Resolved::Scim => Principal::scim(),
        }
    }

    /// `VectispirePrincipal.credentialRestriction()`: what the credential itself narrows the account to. A session,
    /// an agent and the SCIM client carry none; an integration key carries its own.
    pub fn credential_restriction(&self) -> Visibility {
        match self {
            Resolved::Integration(integration) => integration.restriction.clone(),
            _ => Visibility::everything(),
        }
    }

    /// The audit entry's actor — `VectispirePrincipal.getName()`.
    pub fn actor(&self) -> String {
        match self {
            Resolved::Session { account, .. } => account.username.clone(),
            Resolved::Integration(integration) => attribution(&integration.owner.username, &integration.key_name),
            Resolved::Agent { agent, .. } => format!("agent:{}", agent.name),
            Resolved::Scim => "anonymous".to_owned(),
        }
    }
}

/// `VectispirePrincipal.attribution`: the account, and the key beside it, within the audit log's 255-character actor
/// column — the key's name cut first, then the account's.
pub fn attribution(username: &str, key_name: &str) -> String {
    const WIDTH: usize = 255;
    let full = format!("{username} (API key {key_name})");
    if text::utf16_len(&full) <= WIDTH {
        return full;
    }
    let without_name = format!("{username} (API key …)");
    let without_len = text::utf16_len(&without_name);
    if without_len <= WIDTH {
        let room = WIDTH.saturating_sub(without_len);
        return format!("{username} (API key {}…)", clip_utf16(key_name, room));
    }
    let suffix = " (API key …)";
    format!("{}{suffix}", clip_utf16(username, WIDTH.saturating_sub(text::utf16_len(suffix))))
}

/// A request for an integration key — `ApiKeyAdministrationService.Request`.
#[derive(Clone, Debug, Default)]
pub struct KeyRequest {
    pub name: Option<String>,
    /// `None` is the field absent; an element `None` is a JSON `null` in the list.
    pub scopes: Option<Vec<Option<String>>>,
    pub target_kind: Option<String>,
    pub target_id: Option<i64>,
    pub expires_in_days: Option<i32>,
}

/// A key just issued, and the one occurrence of its plaintext.
#[derive(Debug)]
pub struct IssuedIntegrationKey {
    pub key: KeyView,
    pub secret: Secret,
    /// The `API_KEY_CREATED` entry's description, for the caller to write with its actor.
    pub audit_description: String,
}

/// Why issuing failed: a refusal the caller answers 400 with, or the store.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error(transparent)]
    Refused(#[from] IssueRefusal),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The credential store and its rules.
#[derive(Debug, Clone)]
pub struct CredentialService {
    db: Db,
    clock: Arc<dyn Clock>,
    policy: SessionPolicy,
    agents: Arc<dyn AgentDirectory>,
    scim: ScimToken,
}

impl CredentialService {
    pub fn new(
        db: Db,
        clock: Arc<dyn Clock>,
        policy: SessionPolicy,
        agents: Arc<dyn AgentDirectory>,
        scim: ScimToken,
    ) -> CredentialService {
        CredentialService { db, clock, policy, agents, scim }
    }

    // ── sessions ─────────────────────────────────────────────────────────────────────────────

    /// `AuthService.resolve`: the session a token opens, refreshing its activity at the policy's grain.
    ///
    /// The presented token is hashed before it touches the store. An expired session is **deleted** rather than
    /// merely refused, so the table does not grow with rows that will never serve again.
    pub async fn resolve_session(&self, token: &str) -> Result<Option<SessionView>, StoreError> {
        if !sessions::is_session_token_shape(token) {
            return Ok(None);
        }
        let Some(row) = session_store::find(&self.db, &sessions::hash_of(token)).await? else {
            return Ok(None);
        };
        let now = self.clock.now();
        if !sessions::is_active(row.created_at, row.last_seen_at, now, &self.policy) {
            session_store::delete(&self.db, &row.token_hash).await?;
            return Ok(None);
        }
        if !sessions::should_record_activity(row.last_seen_at, now, &self.policy) {
            return Ok(Some(row.into()));
        }
        session_store::touch(&self.db, &row.token_hash, now).await?;
        Ok(Some(SessionView { last_seen_at: now, ..row.into() }))
    }

    /// `AuthService.activeUserOf` / `activeAccount`: the account, if it may still act.
    pub async fn active_account(&self, user_id: i64) -> Result<Option<AccountView>, StoreError> {
        Ok(accounts::find(&self.db, user_id).await?.filter(|row| row.is_active).map(AccountView::of))
    }

    /// The bearer filter's session path: the session, then its account — a deactivated account's session is closed
    /// here rather than honoured until it expires.
    pub async fn authenticate_session(&self, token: &str) -> Result<Option<Resolved>, StoreError> {
        let Some(session) = self.resolve_session(token).await? else {
            return Ok(None);
        };
        match self.active_account(session.user_id).await? {
            Some(account) => Ok(Some(Resolved::Session { account, session })),
            None => {
                self.revoke(&session).await?;
                Ok(None)
            }
        }
    }

    /// Opens a session for an account — the row a password, a code or an identity provider leads to.
    pub async fn open_session(
        &self,
        user_id: i64,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<IssuedSession, StoreError> {
        let now = self.clock.now();
        let minted = sessions::issue();
        let row = SessionRow {
            token_hash: minted.hash,
            user_id,
            created_at: now,
            last_seen_at: now,
            expires_at: plus(now, self.policy.absolute_lifetime),
            user_agent: user_agent.map(|agent| clip_utf16(agent, 255).to_owned()),
            ip_address: ip_address.map(str::to_owned),
        };
        session_store::insert(&self.db, &row).await?;
        Ok(IssuedSession { session: row.into(), token: minted.token })
    }

    /// `AuthService.revoke`: a real logout — the row disappears and the token is worth nothing.
    pub async fn revoke(&self, session: &SessionView) -> Result<(), StoreError> {
        session_store::delete(&self.db, &session.token_hash).await?;
        Ok(())
    }

    /// `AuthService.revokeAllForUser`: every session of an account — after a password change, a role change, a
    /// deactivation, and the password lift.
    pub async fn revoke_all_for_user(&self, user_id: i64) -> Result<u64, StoreError> {
        session_store::delete_by_user(&self.db, user_id).await
    }

    /// An account's other sessions, keeping the one making the request — its own password change.
    pub async fn revoke_others(&self, user_id: i64, keep_token_hash: &str) -> Result<u64, StoreError> {
        session_store::delete_by_user_except(&self.db, user_id, keep_token_hash).await
    }

    /// `SessionCleanupService.pruneSessions`: the rows past their absolute lifetime.
    pub async fn purge_expired(&self) -> Result<u64, StoreError> {
        session_store::delete_expired(&self.db, self.clock.now()).await
    }

    /// `countActiveByUser`, for the administration screen.
    pub async fn count_active_by_user(&self) -> Result<Vec<(i64, i64)>, StoreError> {
        session_store::count_active_by_user(&self.db, self.clock.now()).await
    }

    /// `AuthService.openHandoff`: the single sign-on hand-off — a row the redirect's cookie names, stored under its
    /// own hash so the bearer route never finds it, and expiring with the cookie.
    pub async fn open_handoff(
        &self,
        user_id: i64,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<IssuedSession, StoreError> {
        let now = self.clock.now();
        let minted = sessions::issue();
        let row = SessionRow {
            token_hash: sessions::handoff_hash_of(minted.token.expose()),
            user_id,
            created_at: now,
            last_seen_at: now,
            expires_at: plus(now, HANDOFF_LIFETIME),
            user_agent: user_agent.map(|agent| clip_utf16(agent, 255).to_owned()),
            ip_address: ip_address.map(str::to_owned),
        };
        session_store::insert(&self.db, &row).await?;
        Ok(IssuedSession { session: row.into(), token: minted.token })
    }

    /// `AuthService.resolveHandoff`: the hand-off a cookie names, if it is still waiting.
    pub async fn resolve_handoff(&self, token: &str) -> Result<Option<SessionView>, StoreError> {
        if text::java_is_blank(token) {
            return Ok(None);
        }
        let Some(row) = session_store::find(&self.db, &sessions::handoff_hash_of(token)).await? else {
            return Ok(None);
        };
        if plus(row.created_at, HANDOFF_LIFETIME) < self.clock.now() {
            session_store::delete(&self.db, &row.token_hash).await?;
            return Ok(None);
        }
        Ok(Some(row.into()))
    }

    /// `AuthService.exchangeOnce`: trades a hand-off for a fresh session, once — the delete's row count decides, so
    /// of two exchanges of one cookie only one gets a session.
    pub async fn exchange_once(&self, handoff: &SessionView) -> Result<Option<IssuedSession>, StoreError> {
        if session_store::delete(&self.db, &handoff.token_hash).await? != 1 {
            return Ok(None);
        }
        self.open_session(handoff.user_id, handoff.user_agent.as_deref(), handoff.ip_address.as_deref()).await.map(Some)
    }

    // ── API keys ─────────────────────────────────────────────────────────────────────────────

    /// `ApiKeyAuthService.resolve`: the key when it is usable. It never says why not — telling "unknown" from
    /// "expired" tells whoever is probing which half of a guess was right.
    pub async fn resolve_key(&self, presented: &str) -> Result<Option<KeyView>, StoreError> {
        let trimmed = java_trim(presented);
        let Some(prefix) = api_keys::lookup_prefix(trimmed) else {
            return Ok(None);
        };
        let as_of = self.clock.now();
        for candidate in key_store::find_by_prefix(&self.db, prefix).await? {
            if !phc::verify(trimmed, &candidate.key_hash) {
                continue;
            }
            // Refused, and its row kept: the audit trail needs to know it existed.
            if candidate.expires_at.is_some_and(|expires| expires <= as_of) {
                return Ok(None);
            }
            // Recorded without waiting; the view keeps the value it was read with, as Java's entity does.
            key_store::mark_used(&self.db, candidate.id, as_of).await?;
            return Ok(Some(candidate.into()));
        }
        Ok(None)
    }

    /// `ApiKeyAuthService.integrationFor`: the account and narrowing an integration key carries — none for an agent's
    /// key, a key issued before keys had an owner, or a key whose account is gone or deactivated: a key must not
    /// outlive the account whose authority it borrows.
    pub async fn integration_for(&self, key: &KeyView) -> Result<Option<Integration>, StoreError> {
        if key.has_scope(ApiKeyScope::Agent) {
            return Ok(None);
        }
        let Some(owner) = key.owner_user_id else {
            return Ok(None);
        };
        let scopes: Vec<ApiKeyScope> =
            api_keys::scopes_of(Some(&key.scopes)).into_iter().filter(|scope| *scope != ApiKeyScope::Agent).collect();
        Ok(self.active_account(owner).await?.map(|owner| Integration {
            owner,
            key_id: key.id,
            key_name: key.name.clone(),
            scopes,
            restriction: api_keys::restriction_of(key.target_kind.as_deref(), key.target_id),
        }))
    }

    /// The bearer filter's key path: an agent's key becomes its agent, an integration key its account. A key with the
    /// `agent` scope and no agent behind it is nobody.
    pub async fn authenticate_key(&self, presented: &str) -> Result<Option<Resolved>, StoreError> {
        let Some(key) = self.resolve_key(presented).await? else {
            return Ok(None);
        };
        if key.has_scope(ApiKeyScope::Agent) {
            return Ok(self.agents.by_api_key(key.id).await?.map(|agent| Resolved::Agent { agent, key_id: key.id }));
        }
        Ok(self.integration_for(&key).await?.map(Resolved::Integration))
    }

    /// `ApiKeyAdministrationService.issue`: an integration key, acting for `owner` and narrowed as asked.
    pub async fn issue_integration_key(
        &self,
        owner: i64,
        request: &KeyRequest,
        targets: &dyn IssuerSees,
    ) -> Result<IssuedIntegrationKey, IssueError> {
        let name = api_keys::normalize_name(request.name.as_deref())?;
        let scopes = api_keys::normalize_scopes(request.scopes.as_deref())?;
        let lifetime = api_keys::normalize_lifetime(request.expires_in_days)?;
        if scopes.contains(&ApiKeyScope::Agent) {
            // An agent's key is created with the agent, which binds it to that agent. Issued here it would belong to
            // nobody and authenticate nowhere.
            return Err(IssueRefusal::InvalidKey(
                "The agent scope is not issued here: declare the agent, which creates its key.".to_owned(),
            )
            .into());
        }
        let target = api_keys::normalize_target(request.target_kind.as_deref(), request.target_id)?;
        if let Some(target) = target
            && !targets.issuer_sees(owner, target).await?
        {
            let (kind, id) = api_keys::kind_of(target);
            return Err(IssueRefusal::InvalidKey(format!("No {kind} {id} to restrict the key to.")).into());
        }

        let issued = api_keys::generate();
        let now = self.clock.now();
        let (target_kind, target_id) = target.map(api_keys::kind_of).map_or((None, None), |(k, i)| (Some(k), Some(i)));
        let row = KeyRow {
            id: random_uuid(),
            name,
            key_hash: phc::hash(issued.full_key.expose()),
            prefix: Some(issued.prefix),
            created_at: now,
            last_used_at: None,
            scopes: api_keys::stored_scopes(&scopes),
            target_kind: target_kind.map(str::to_owned),
            target_id,
            expires_at: lifetime.map(|days| plus(now, Duration::days(i64::from(days)))),
            owner_user_id: Some(owner),
        };
        key_store::insert(&self.db, &row).await?;
        let audit_description = format!("API key issued: {} ({})", row.name, row.scopes);
        Ok(IssuedIntegrationKey { key: row.into(), secret: issued.full_key, audit_description })
    }

    /// `AgentKeys.issue`: an agent's key under `name`, whose only scope is `agent`. Answers its identifier, which the
    /// agent row that points at it is saved with after.
    pub async fn issue_agent_key(&self, name: &str) -> Result<(Uuid, Secret), StoreError> {
        let issued = api_keys::generate();
        let row = KeyRow {
            id: random_uuid(),
            name: name.to_owned(),
            key_hash: phc::hash(issued.full_key.expose()),
            prefix: Some(issued.prefix),
            created_at: self.clock.now(),
            last_used_at: None,
            scopes: ApiKeyScope::Agent.wire_name().to_owned(),
            target_kind: None,
            target_id: None,
            expires_at: None,
            owner_user_id: None,
        };
        key_store::insert(&self.db, &row).await?;
        Ok((row.id, issued.full_key))
    }

    /// A key by its id, hash withheld.
    pub async fn key(&self, id: Uuid) -> Result<Option<KeyView>, StoreError> {
        Ok(key_store::find(&self.db, id).await?.map(KeyView::from))
    }

    /// Revoking deletes the row; answers whether there was one. Who may revoke whose key — a governor's key is
    /// administered by a governor — is the route's decision, made before this.
    pub async fn revoke_key(&self, id: Uuid) -> Result<bool, StoreError> {
        Ok(key_store::delete(&self.db, id).await? > 0)
    }

    /// `revokeOwnedBy`: the keys an account issued.
    pub async fn revoke_keys_owned_by(&self, owner: i64) -> Result<u64, StoreError> {
        key_store::delete_owned_by(&self.db, owner).await
    }

    // ── SCIM ─────────────────────────────────────────────────────────────────────────────────

    /// Whether `token` is the SCIM token **and SCIM is switched on**, compared in constant time. A token left in the
    /// environment of an installation that switched SCIM off authenticates nothing.
    pub fn scim_matches(&self, token: &str) -> bool {
        self.scim.enabled && self.scim.token.as_ref().is_some_and(|expected| secret_equals(token, expected.expose()))
    }
}

/// `instant + duration`, at the far future when it would overflow.
fn plus(instant: OffsetDateTime, duration: Duration) -> OffsetDateTime {
    instant.checked_add(duration).unwrap_or(OffsetDateTime::new_utc(time::Date::MAX, time::Time::MIDNIGHT))
}

/// A version-4 UUID, as Hibernate's `GenerationType.UUID` makes one.
fn random_uuid() -> Uuid {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

/// A store failure behind the chain's trait: logged, and answered as "no credential" — the request then meets the
/// 401 every unknown credential meets. Java's filter let the exception through, a 500; neither tells the caller
/// anything, and failing closed is the half that matters.
fn closed<T>(outcome: Result<Option<T>, StoreError>, what: &str) -> Option<T> {
    outcome.unwrap_or_else(|failure| {
        tracing::error!(error = %failure, "{what} could not be resolved; the request is treated as unauthenticated");
        None
    })
}

impl Credentials for CredentialService {
    fn session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>> {
        Box::pin(async move { closed(self.authenticate_session(token).await, "a session").map(|r| r.principal()) })
    }

    fn api_key<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>> {
        Box::pin(async move { closed(self.authenticate_key(token).await, "an API key").map(|r| r.principal()) })
    }

    fn scim<'a>(&'a self, token: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move { self.scim_matches(token) })
    }
}
