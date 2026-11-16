//! The access routes served so far against the contract they must not change: documented under the same method and
//! path, with Java's operation ids, out of `cp-contract`'s `not-yet-ported/` since the commit that ported them — then
//! the router probed, so a route declared and not registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_access::accounts::{Accounts, Audit, AuditRecord};
use vectispire_cp_access::api_key_administration::{ApiKeyAdministration, ApiKeyParts};
use vectispire_cp_access::credentials::{CredentialService, ScimToken, SessionPolicy, SystemClock};
use vectispire_cp_access::teams::{TeamAdministration, TeamParts};
use vectispire_cp_access::{
    AccessError, AccessSettings, Administration, CredentialTables, GrantableTargets, IssuerVisibility, Labels,
    SqlAccountStore, TargetGrant, VisibilityService, administration_routes,
};
use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_db::ScanTarget;
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};

/// Method, path, operation id, and the query parameters the handler reads — all optional.
const DECLARED: &[(&str, &str, &str, &[&str])] = &[
    ("GET", "/api/v1/users", "list_1", &["limit", "offset"]),
    ("POST", "/api/v1/users", "create", &[]),
    ("PATCH", "/api/v1/users/{id}", "update_3", &[]),
    ("DELETE", "/api/v1/users/{id}/password-change-requirement", "clearPasswordChangeRequirement", &[]),
    ("DELETE", "/api/v1/users/{id}/second-factor", "resetSecondFactor", &[]),
    ("GET", "/api/v1/users/{id}/targets", "targets", &["limit", "offset"]),
    ("PUT", "/api/v1/users/{id}/targets", "setTargets", &[]),
    ("DELETE", "/api/v1/users/{id}", "remove", &[]),
    ("GET", "/api/v1/account-requests", "listAccountRequests", &["limit", "offset"]),
    ("POST", "/api/v1/account-requests/{id}/approve", "approveAccountRequest", &[]),
    ("POST", "/api/v1/account-requests/{id}/reject", "rejectAccountRequest", &[]),
    ("GET", "/api/v1/teams", "list_2", &["limit", "offset"]),
    ("POST", "/api/v1/teams", "create_1", &[]),
    ("PATCH", "/api/v1/teams/{id}", "rename", &[]),
    ("DELETE", "/api/v1/teams/{id}", "remove_1", &[]),
    ("GET", "/api/v1/teams/{id}/members", "members", &["limit", "offset"]),
    ("PUT", "/api/v1/teams/{id}/members", "setMembers", &[]),
    ("GET", "/api/v1/teams/{id}/targets", "targets_1", &["limit", "offset"]),
    ("PUT", "/api/v1/teams/{id}/targets", "setTargets_1", &[]),
    ("PUT", "/api/v1/teams/{id}/webhook", "setWebhook", &[]),
    ("GET", "/api/v1/api-keys", "list_15", &["limit", "offset"]),
    ("POST", "/api/v1/api-keys", "create_8", &[]),
    ("DELETE", "/api/v1/api-keys/{id}", "remove_9", &[]),
    ("GET", "/api/v1/api-keys/targets", "targets_2", &[]),
    ("POST", "/api/v1/auth/change-password", "changePassword", &[]),
    ("POST", "/api/v1/auth/login", "login", &[]),
    ("GET", "/api/v1/auth/me", "me", &[]),
    ("GET", "/api/v1/auth/methods", "methods", &[]),
    ("POST", "/api/v1/auth/mfa/disable", "disableMfa", &[]),
    ("POST", "/api/v1/auth/mfa/enable", "enableMfa", &[]),
    ("POST", "/api/v1/auth/mfa/setup", "setupMfa", &[]),
    ("POST", "/api/v1/auth/mfa/verify", "verifyMfa", &[]),
    ("DELETE", "/api/v1/auth/session", "logout", &[]),
    ("POST", "/api/v1/auth/session/exchange", "exchange", &[]),
];

/// The ports the probe never reaches: it asks the routes' shape, not a grant.
struct Nobody;

impl Audit for Nobody {
    async fn record(&self, _: AuditRecord) {}
}

impl GrantableTargets for Nobody {
    fn targets_in<'a>(&'a self, _: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<Vec<ScanTarget>, AccessError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn named<'a>(
        &'a self,
        _: &'a [vectispire_cp_access::visibility::Grant],
    ) -> BoxFuture<'a, Result<Vec<TargetGrant>, AccessError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn project_exists(&self, _: i64) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async { Ok(false) })
    }
    fn exists(&self, _: ScanTarget) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async { Ok(false) })
    }
    fn labels(&self) -> BoxFuture<'_, Result<Labels, AccessError>> {
        Box::pin(async { Ok(Labels::default()) })
    }
}

impl AccessSettings for Nobody {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async { Ok(String::new()) })
    }
}

#[derive(Debug)]
struct NoAgents;

impl vectispire_cp_access::credentials::AgentDirectory for NoAgents {
    fn by_api_key<'a>(
        &'a self,
        _: uuid::Uuid,
    ) -> BoxFuture<
        'a,
        Result<Option<vectispire_cp_access::credentials::AgentRef>, vectispire_cp_access::credentials::StoreError>,
    > {
        Box::pin(async { Ok(None) })
    }
}

/// `AuthController`'s routes over a flow on the unreachable database, as the binary composes them.
fn sign_in_routes(db: vectispire_cp_db::Db) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    let door = VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    let clock: vectispire_cp_access::throttle::SharedClock = Arc::new(SystemClock);
    let credentials = Arc::new(CredentialService::new(
        db.clone(),
        clock.clone(),
        SessionPolicy::default(),
        Arc::new(NoAgents),
        ScimToken::default(),
    ));
    let flow = vectispire_cp_access::sign_in::SignInFlow::new(vectispire_cp_access::sign_in::SignInParts {
        users: SqlAccountStore::new(db.clone(), CredentialTables),
        audit: Silent,
        store: vectispire_cp_access::SqlSignInStore::new(db),
        sessions: credentials.clone(),
        seal: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        clock,
        methods: vectispire_cp_access::sign_in::SignInMethodPolicy::new(false, true),
        provider_label: None,
    });
    vectispire_cp_access::auth_routes(Arc::new(flow), credentials, vectispire_cp_access::Branding::of(None, None))
}

/// The sign-in flow's audit, never written: the probe reads the routes' shape.
#[derive(Clone)]
struct Silent;

impl Audit for Silent {
    async fn record(&self, _: AuditRecord) {}
}

fn unreachable_db() -> vectispire_cp_db::Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    vectispire_cp_db::Db::connect_lazy(&settings).unwrap()
}

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let db = unreachable_db();
    let clock: vectispire_cp_access::throttle::SharedClock = Arc::new(SystemClock);
    let targets: Arc<dyn GrantableTargets> = Arc::new(Nobody);
    let credentials = CredentialService::new(
        db.clone(),
        clock.clone(),
        SessionPolicy::default(),
        Arc::new(NoAgents),
        ScimToken::default(),
    );
    let visibility = VisibilityService::new(db.clone(), Arc::new(Nobody), targets.clone());
    let mut entries = administration_routes(Administration {
        accounts: Arc::new(Accounts::new(SqlAccountStore::new(db.clone(), CredentialTables), Nobody, clock.clone())),
        account_targets: Arc::new(vectispire_cp_access::account_targets::AccountTargets::new(
            db.clone(),
            Nobody,
            targets.clone(),
        )),
        teams: Arc::new(TeamAdministration::new(TeamParts {
            db: db.clone(),
            audit: Nobody,
            clock: clock.clone(),
            outbound: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
            policy: Arc::new(vectispire_cp_settings::Settings::new(db.clone())),
            targets: targets.clone(),
            integrations: vectispire_cp_settings::Integrations::new(
                db.clone(),
                Vec::new(),
                Arc::new(time::OffsetDateTime::now_utc),
            ),
        })),
        keys: Arc::new(ApiKeyAdministration::new(ApiKeyParts {
            db: db.clone(),
            credentials,
            targets: targets.clone(),
            issuer_sees: Arc::new(IssuerVisibility::new(db.clone(), visibility, targets)),
            audit: Nobody,
            clock,
        })),
    });
    // Every one of the four administration controllers is `@RequiresAdministrator` on its class.
    for entry in &entries {
        assert_eq!(entry.decl().access, Access::Administrator, "{} {}", entry.decl().method, entry.decl().path);
    }
    entries.extend(sign_in_routes(db.clone()));
    assert_eq!(entries.len(), DECLARED.len());
    assert!(entries.iter().all(|entry| entry.decl().accepts_api_key.is_none()), "no access route invites an API key");
    // `AuthController`'s markers on its methods: signing in is anybody's, the rest an account's; `@PasswordChangeGate`
    // on the three an account owing a password change still reaches.
    let marker = |method: &str, path: &str| {
        let decl =
            entries.iter().find(|entry| entry.decl().method == method && entry.decl().path == path).unwrap().decl();
        (decl.access, decl.allows_pending_password_change)
    };
    for path in ["/api/v1/auth/login", "/api/v1/auth/mfa/verify", "/api/v1/auth/session/exchange"] {
        assert_eq!(marker("POST", path), (Access::Anonymous, false), "{path}");
    }
    assert_eq!(marker("GET", "/api/v1/auth/methods"), (Access::Anonymous, false));
    for path in ["/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/enable", "/api/v1/auth/mfa/disable"] {
        assert_eq!(marker("POST", path), (Access::Account, false), "{path}");
    }
    assert_eq!(marker("DELETE", "/api/v1/auth/session"), (Access::Account, true));
    assert_eq!(marker("POST", "/api/v1/auth/change-password"), (Access::Account, true));
    assert_eq!(marker("GET", "/api/v1/auth/me"), (Access::Account, true));

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            query.iter().fold(RouteDecl::new(method, path, id), |route, name| route.query(name, false))
        })
        .collect();
    let document = Document::embedded();
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    let not_ours = Allowlist::all_but(&document, &ours);
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    let mut routes = Routes::new(NoVisibility);
    for entry in entries {
        routes = routes.route(entry);
    }
    let chain = Arc::new(Chain::new(
        ChainConfig::default(),
        Arc::new(StaticCredentials::default()),
        Arc::new(RecordingAudit::default()),
    ));
    let router = routes.build(&chain, None).unwrap();
    assert_none(&probe(&router, &document, &not_ours).await);
}
