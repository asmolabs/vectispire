//! A control plane's HTTP layer assembled the way Phase 1 will assemble it — the chain, the routes the Java controllers
//! declare, the interface — over the test doubles of `credentials`. Shared by the suites in this directory.

#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use http::{Request, Response, header};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::buckets::Clock;
use vectispire_cp_http::chain::{Chain, ChainConfig, Trace};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::extract::{Caller, JsonBody, Scoped};
use vectispire_cp_http::interface::Interface;
use vectispire_cp_http::principal::{Account, ApiKeyScope, Principal, Role};
use vectispire_cp_http::problem::Problem;
use vectispire_cp_http::routes::{Route, Routes, VisibilityOf, require_visible};

/// A clock a test moves by hand.
#[derive(Debug, Default)]
pub struct ManualClock(std::sync::atomic::AtomicU64);

impl ManualClock {
    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(u64::try_from(by.as_nanos()).expect("small"), std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn nanos(&self) -> u128 {
        u128::from(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

pub const ADMIN: &str = "tok-admin";
pub const PENDING: &str = "tok-pending";
pub const USER: &str = "tok-user";
pub const AUDITOR: &str = "tok-auditor";
pub const CISO: &str = "tok-ciso";
pub const CHAMPION: &str = "tok-champion";
pub const UNREADABLE: &str = "tok-typo";
pub const READ_KEY: &str = "zsk_read-key";
pub const AGENT_KEY: &str = "zsk_agent-key";
pub const SCIM_TOKEN: &str = "scim-token-invented";

fn account(name: &str, role: Option<Role>, pending: bool) -> Account {
    Account { username: name.to_owned(), role, must_change_password: pending }
}

pub fn credentials() -> StaticCredentials {
    StaticCredentials::default()
        .session(ADMIN, Principal::session(account("admin", Some(Role::Superuser), false)))
        .session(PENDING, Principal::session(account("admin", Some(Role::Superuser), true)))
        .session(USER, Principal::session(account("vs-rs-http-user", Some(Role::User), false)))
        .session(AUDITOR, Principal::session(account("auditor", Some(Role::Auditor), false)))
        .session(CISO, Principal::session(account("ciso", Some(Role::Ciso), false)))
        .session(CHAMPION, Principal::session(account("champion", Some(Role::SecurityChampion), false)))
        .session(UNREADABLE, Principal::session(account("typo", None, false)))
        .session("tok-unreadable", Principal::session(account("typo", None, false)))
        .key(
            READ_KEY,
            Principal::integration(account("admin", Some(Role::Superuser), false), "key-1", vec![ApiKeyScope::Read]),
        )
        .key(AGENT_KEY, Principal::agent("agent-1"))
        .scim_token(SCIM_TOKEN)
}

/// What a scoped route resolves for a caller: the account's name, so a test can see the value arrive.
#[derive(Debug)]
pub struct NameOf;

impl VisibilityOf<String> for NameOf {
    fn of<'a>(&'a self, principal: &'a Principal) -> vectispire_cp_http::credentials::BoxFuture<'a, String> {
        Box::pin(async move { principal.account.as_ref().map_or_else(|| "none".to_owned(), |a| a.username.clone()) })
    }
}

pub struct App {
    pub router: Router,
    pub audit: Arc<RecordingAudit>,
    pub trace: Trace,
    pub clock: Arc<ManualClock>,
    pub chain: Arc<Chain>,
}

#[derive(serde::Deserialize)]
struct Login {
    #[allow(dead_code)]
    username: String,
}

#[derive(serde::Deserialize)]
struct Repository {
    name: String,
}

fn json(body: &'static str) -> Response<Body> {
    Response::builder().header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).expect("a response")
}

async fn login(JsonBody(_): JsonBody<Login>) -> Problem {
    Problem::handler(http::StatusCode::UNAUTHORIZED, "Bad credentials.")
}

async fn empty_list(Scoped(_who): Scoped<String>) -> Response<Body> {
    json("[]")
}

async fn create_repository(JsonBody(repository): JsonBody<Repository>) -> Problem {
    Problem::handler(
        http::StatusCode::CONFLICT,
        format!(
            "This repository is already registered as \"{}\" (id 1), on branch main, at its root. Edit that target, or choose another branch or sub-path.",
            repository.name
        ),
    )
    .caused_by("target-already-registered")
    .with("existingRepositoryId", 1)
}

async fn project(
    axum::extract::Path(id): axum::extract::Path<u64>,
    Scoped(_who): Scoped<String>,
) -> Result<Response<Body>, Problem> {
    // The row is absent, or not the caller's: the same sentence either way.
    let _ = id;
    require_visible(None::<u64>, |_| true, "Project not found.").map(|_| json("{}"))
}

async fn whoami(Caller(principal): Caller) -> Response<Body> {
    let name = principal.account.map_or_else(|| "agent".to_owned(), |a| a.username);
    Response::builder().header(header::CONTENT_TYPE, "text/plain").body(Body::from(name)).expect("a response")
}

async fn who_scoped(Scoped(who): Scoped<String>) -> Response<Body> {
    Response::builder().header(header::CONTENT_TYPE, "text/plain").body(Body::from(who)).expect("a response")
}

async fn nothing() -> Response<Body> {
    Response::builder().header(header::CONTENT_TYPE, "text/plain").body(Body::from("ok")).expect("a response")
}

/// A service's `AccessDeniedException`, with the reason the audit log keeps.
async fn refused_by_the_service() -> Response<Body> {
    vectispire_cp_http::chain::denied("the platform governor takes no triage decision.")
}

async fn drain(body: Body) -> Result<Response<Body>, Problem> {
    use http_body_util::BodyExt;
    match body.collect().await {
        Ok(collected) => Ok(Response::new(Body::from(format!("{} bytes", collected.to_bytes().len())))),
        Err(error) => match vectispire_cp_http::limits::find_too_large(&error) {
            Some(too_large) => Err(Problem::handler(
                http::StatusCode::PAYLOAD_TOO_LARGE,
                vectispire_cp_http::limits::too_large_detail(too_large.ceiling),
            )),
            None => Err(Problem::handler(http::StatusCode::BAD_REQUEST, "unreadable")),
        },
    }
}

async fn health() -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/vnd.spring-boot.actuator.v3+json")
        .body(Body::from(r#"{"groups":["liveness","readiness"],"status":"UP"}"#))
        .expect("a response")
}

async fn actuator_json() -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/vnd.spring-boot.actuator.v3+json")
        .body(Body::from(r#"{"names":[]}"#))
        .expect("a response")
}

async fn pem() -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-pem-file;charset=UTF-8")
        .header(header::CONTENT_DISPOSITION, "attachment; filename=\"vectispire-signing-key.pub\"")
        .body(Body::from("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"))
        .expect("a response")
}

/// The routes the Java controllers declare for the paths the goldens visit, with the same markers.
pub fn routes() -> Routes<String> {
    Routes::new(NameOf)
        .route(Route::post("/api/v1/auth/login").requires(Access::Anonymous).names_no_target().handler(login))
        .route(
            Route::get("/api/v1/auth/me")
                .requires(Access::Account)
                .names_no_target()
                .allows_pending_password_change()
                .handler(whoami),
        )
        .route(
            Route::get("/api/v1/repositories")
                .requires(Access::Account)
                .scoped()
                .accepts_api_key(ApiKeyScope::Read)
                .handler(empty_list),
        )
        .route(
            Route::post("/api/v1/repositories")
                .requires(Access::SecurityLead)
                .names_no_target()
                .handler(create_repository),
        )
        .route(
            Route::post("/api/v1/repositories/{id}/scan")
                .requires(Access::WriteAccount)
                .scoped()
                .accepts_api_key(ApiKeyScope::Scan)
                .handler(nothing),
        )
        .route(Route::get("/api/v1/users").requires(Access::Administrator).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/projects/{id}").requires(Access::Account).scoped().handler(project))
        .route(Route::get("/api/v1/agent/jobs").requires(Access::AgentKey).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/crypto/public-key.pub").requires(Access::Anonymous).names_no_target().handler(pem))
        .route(Route::get("/actuator/health").requires(Access::Anonymous).names_no_target().handler(health))
        .route(Route::get("/actuator/metrics").requires(Access::Anonymous).names_no_target().handler(actuator_json))
        .route(Route::get("/v3/api-docs").requires(Access::Anonymous).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/whoami").requires(Access::Account).names_no_target().handler(whoami))
        .route(Route::get("/api/v1/scoped").requires(Access::Account).scoped().handler(who_scoped))
        .route(
            Route::post("/api/v1/tickets/webhook/{token}")
                .requires(Access::Anonymous)
                .names_no_target()
                .handler(nothing),
        )
        .route(Route::post("/api/v1/drain").requires(Access::Account).names_no_target().handler(drain))
        .route(Route::post("/api/v1/rule-sets").requires(Access::SecurityLead).names_no_target().handler(drain))
        .route(Route::post("/api/v1/open-for-keys").requires(Access::Anonymous).names_no_target().handler(nothing))
        .route(Route::get("/scim/v2/Users").requires(Access::Administrator).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/_t/anonymous").requires(Access::Anonymous).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/_t/account").requires(Access::Account).names_no_target().handler(nothing))
        .route(
            Route::get("/api/v1/_t/administrator").requires(Access::Administrator).names_no_target().handler(nothing),
        )
        .route(
            Route::get("/api/v1/_t/governance-read")
                .requires(Access::GovernanceRead)
                .names_no_target()
                .handler(nothing),
        )
        .route(
            Route::get("/api/v1/_t/platform-governor")
                .requires(Access::PlatformGovernor)
                .names_no_target()
                .handler(nothing),
        )
        .route(Route::get("/api/v1/_t/security-lead").requires(Access::SecurityLead).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/_t/write").requires(Access::WriteAccount).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/agent/_t").requires(Access::AgentKey).names_no_target().handler(nothing))
        .route(Route::get("/api/v1/_t/misuse").requires(Access::Account).names_no_target().handler(who_scoped))
        .route(
            Route::get("/api/v1/_t/denied").requires(Access::Account).names_no_target().handler(refused_by_the_service),
        )
        .route(Route::get("/api/v1/typo").requires(Access::Administrator).names_no_target().handler(nothing))
}

pub fn interface(dir: &Path) -> Option<Interface> {
    Interface::load(dir)
}

pub fn app_with(config: ChainConfig, interface_dir: Option<&Path>) -> App {
    let audit = Arc::new(RecordingAudit::default());
    let trace = Trace::new();
    let clock = Arc::new(ManualClock::default());
    let chain = Arc::new(
        Chain::with_clock(config, Arc::new(credentials()), audit.clone(), clock.clone()).with_trace(trace.clone()),
    );
    let router = routes().build(&chain, interface_dir.and_then(interface)).expect("no route twice");
    App { router, audit, trace, clock, chain }
}

pub fn app() -> App {
    app_with(ChainConfig::default(), None)
}

/// An interface directory shaped like the Angular build.
pub fn interface_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::write(dir.path().join("index.html"), "<!doctype html><title>Vectispire</title>").expect("write");
    std::fs::write(dir.path().join("main-TEST.js"), "console.log(1);").expect("write");
    std::fs::create_dir_all(dir.path().join("i18n")).expect("mkdir");
    std::fs::write(dir.path().join("i18n/en.json"), "{}").expect("write");
    dir
}

/// A request from `peer`, as the server hands it to the router: with the connection's address.
pub fn request(method: &str, uri: &str, headers: &[(&str, &str)], body: Body) -> Request<Body> {
    request_from("203.0.113.9:40000", method, uri, headers, body)
}

pub fn request_from(peer: &str, method: &str, uri: &str, headers: &[(&str, &str)], body: Body) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(body).expect("a request");
    request.extensions_mut().insert(ConnectInfo(peer.parse::<SocketAddr>().expect("an address")));
    request
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub async fn send(app: &App, request: Request<Body>) -> Response<Body> {
    app.router.clone().oneshot(request).await.expect("infallible")
}

pub async fn text(response: Response<Body>) -> (http::StatusCode, http::HeaderMap, String) {
    use http_body_util::BodyExt;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("a body").to_bytes();
    (parts.status, parts.headers, String::from_utf8_lossy(&bytes).into_owned())
}
