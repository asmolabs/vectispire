//! The filter chain of `SecurityConfiguration.apiSecurity`, as tower layers **in the same order**.
//!
//! ```text
//! request ─▶ firewall ─▶ client-address ─▶ headers ─▶ login-limit ─▶ webhook-limit ─▶ body-limit
//!         ─▶ bearer-limit ─▶ bearer ─▶ access ─▶ problems ─▶ router
//!                                                              └▶ per route: password-change ─▶ credential-confinement ─▶ role ─▶ handler
//! ```
//!
//! **The order is the behaviour**, and the Java sources say why each position matters:
//!
//! * the **firewall** answers before the headers are written, so its refusals carry none (the `firewall-*` goldens);
//! * **client-address** is first so every later filter, handler and audit entry reads the same address;
//! * **headers** wrap everything after them, the static files included: the document that carries an injected string is
//!   `index.html`, so a policy applied only to `/api` would guard the JSON and leave the page it renders into bare;
//! * the **limits** come before the bearer's resolution: the bearer limiter has to see the request on the way in, to
//!   refuse an address that has already spent its allowance, *and* on the way out, to know whether the token resolved —
//!   merging it into the resolver would put the ceiling inside the thing being measured;
//! * **body-limit** is before any extractor can read a body whole;
//! * **access** — `authorizeHttpRequests` — is after the credential is resolved and before the router, and is not the
//!   authorization: a route's own marker, checked in its gate, is (AGENTS.md, "a role marker is not authorization").
//!
//! [`CHAIN`] names the layers and the route stage; a test drives a request through all of them and compares the order in
//! which they ran with it, so that a layer moved "for tidiness" fails a test that says where it was.

use crate::access::{self, Gate};
use crate::address::{TrustedProxies, client_bucket};
use crate::buckets::{Buckets, Clock, SystemClock};
use crate::credentials::{AccessDenied, Audit, Credentials, SharedWindow};
use crate::extract::ClientAddress;
use crate::limits::{BodyLimits, Counting, too_large_detail};
use crate::principal::{Credential, Principal};
use crate::problem::Problem;
use crate::routing::{self, routed_path};
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use http::{HeaderName, HeaderValue, StatusCode, header};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The layers, outermost first, then the stages every route runs.
pub const CHAIN: [&str; 13] = [
    "firewall",
    "client-address",
    "headers",
    "login-limit",
    "webhook-limit",
    "body-limit",
    "bearer-limit",
    "bearer",
    "access",
    "problems",
    "password-change",
    "credential-confinement",
    "role",
];

/// The content security policy, in one place because it is one sentence. See the Java `SecurityConfiguration` for the
/// reasoning behind each relaxation: `style-src` carries `'unsafe-inline'` because Angular and PrimeNG emit inline styles
/// (measured, not assumed), `script-src` carries neither it nor `'unsafe-eval'`, and HSTS stays absent on purpose —
/// Vectispire is routinely reached over plain HTTP on an internal address, and a Strict-Transport-Security header seen
/// once makes that origin unreachable in that browser. It belongs to the proxy that terminates TLS.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

const UNAUTHENTICATED: &str = "Authentication required: sign in, or send a valid credential as a bearer token.";
const FORBIDDEN: &str = "This credential is not allowed to call this route.";
const API_KEY_HEADER: &str = "X-API-Key";

/// The chain's refusal of a request with no credential: 401, no `WWW-Authenticate` — a browser prompting for basic
/// credentials over a token API helps nobody — and a problem body like every other refusal.
pub fn unauthenticated(path: &str) -> Problem {
    Problem::chain(StatusCode::UNAUTHORIZED, UNAUTHENTICATED).at(path)
}

/// Limits and switches the chain reads. The defaults are the Java side's shipped values.
#[derive(Clone, Debug)]
pub struct ChainConfig {
    /// `vectispire.security.trusted-proxies`.
    pub trusted_proxies: TrustedProxies,
    pub body_limits: BodyLimits,
    /// Sign-in attempts per window per address (`login-attempts-per-window`, `login-attempt-window`).
    pub login_attempts: u64,
    pub login_window: Duration,
    /// Refused bearer tokens per window per address (`bearer-failures-per-window`, `bearer-failure-window`).
    pub bearer_failures: u64,
    pub bearer_window: Duration,
    /// Tracker webhook deliveries per window per address.
    pub webhook_requests: u64,
    pub webhook_window: Duration,
    /// Requests per minute per integration key (`api-key-requests-per-minute`).
    pub api_key_requests_per_minute: u64,
    /// `vectispire.security.anonymous-api-docs`.
    pub anonymous_api_docs: bool,
}

impl Default for ChainConfig {
    fn default() -> ChainConfig {
        ChainConfig {
            trusted_proxies: TrustedProxies::none(),
            body_limits: BodyLimits::default(),
            login_attempts: 10,
            login_window: Duration::from_secs(60),
            bearer_failures: 60,
            bearer_window: Duration::from_secs(300),
            webhook_requests: 300,
            webhook_window: Duration::from_secs(60),
            api_key_requests_per_minute: 600,
            anonymous_api_docs: false,
        }
    }
}

/// A recorder of the layers a request passed through — set in tests, `None` in production, where `visit` is a
/// branch on an `Option`.
#[derive(Clone, Debug, Default)]
pub struct Trace(Arc<Mutex<Vec<&'static str>>>);

impl Trace {
    pub fn new() -> Trace {
        Trace::default()
    }

    pub fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The chain's state: its limits, its buckets, and the three things it asks the rest of the control plane.
#[derive(Debug)]
pub struct Chain {
    pub(crate) config: ChainConfig,
    login: Buckets,
    bearer: Buckets,
    webhook: Buckets,
    pub(crate) keys: Buckets,
    pub(crate) credentials: Arc<dyn Credentials>,
    pub(crate) audit: Arc<dyn Audit>,
    shared_webhook: Option<Arc<dyn SharedWindow>>,
    trace: Option<Trace>,
}

const MAX_BUCKETS: usize = 10_000;

/// A value `<= 0` falls back to the shipped one: a ceiling of zero would refuse every sign-in including the operator's.
fn positive(value: u64, default: u64) -> u64 {
    if value > 0 { value } else { default }
}

fn positive_window(value: Duration, default: Duration) -> Duration {
    if value.is_zero() { default } else { value }
}

impl Chain {
    pub fn new(config: ChainConfig, credentials: Arc<dyn Credentials>, audit: Arc<dyn Audit>) -> Chain {
        Chain::with_clock(config, credentials, audit, Arc::new(SystemClock::new()))
    }

    pub fn with_clock(
        mut config: ChainConfig,
        credentials: Arc<dyn Credentials>,
        audit: Arc<dyn Audit>,
        clock: Arc<dyn Clock>,
    ) -> Chain {
        let defaults = ChainConfig::default();
        config.login_attempts = positive(config.login_attempts, defaults.login_attempts);
        config.login_window = positive_window(config.login_window, defaults.login_window);
        config.bearer_failures = positive(config.bearer_failures, defaults.bearer_failures);
        config.bearer_window = positive_window(config.bearer_window, defaults.bearer_window);
        config.webhook_requests = positive(config.webhook_requests, defaults.webhook_requests);
        config.webhook_window = positive_window(config.webhook_window, defaults.webhook_window);
        config.api_key_requests_per_minute =
            positive(config.api_key_requests_per_minute, defaults.api_key_requests_per_minute);
        Chain {
            login: Buckets::new(config.login_attempts, config.login_window, MAX_BUCKETS, clock.clone()),
            bearer: Buckets::new(config.bearer_failures, config.bearer_window, MAX_BUCKETS, clock.clone()),
            webhook: Buckets::new(config.webhook_requests, config.webhook_window, MAX_BUCKETS, clock.clone()),
            keys: Buckets::new(config.api_key_requests_per_minute, Duration::from_secs(60), MAX_BUCKETS, clock),
            config,
            credentials,
            audit,
            shared_webhook: None,
            trace: None,
        }
    }

    /// The webhook's second budget, counted across instances.
    pub fn with_shared_webhook_window(mut self, shared: Arc<dyn SharedWindow>) -> Chain {
        self.shared_webhook = Some(shared);
        self
    }

    pub fn with_trace(mut self, trace: Trace) -> Chain {
        self.trace = Some(trace);
        self
    }

    /// Forgets every counted attempt — the `reset()` the Java filters give their tests.
    pub fn reset(&self) {
        self.login.clear();
        self.bearer.clear();
        self.webhook.clear();
        self.keys.clear();
    }

    pub(crate) fn visit(&self, layer: &'static str) {
        if let Some(trace) = &self.trace {
            trace.0.lock().unwrap_or_else(PoisonError::into_inner).push(layer);
        }
    }

    /// Wraps `router` in the chain, in [`CHAIN`]'s order.
    pub fn apply(self: &Arc<Chain>, router: Router) -> Router {
        // `layer` makes the last one outermost, so the list reads innermost first.
        router
            .layer(middleware::from_fn_with_state(self.clone(), problems))
            .layer(middleware::from_fn_with_state(self.clone(), access))
            .layer(middleware::from_fn_with_state(self.clone(), bearer))
            .layer(middleware::from_fn_with_state(self.clone(), bearer_limit))
            .layer(middleware::from_fn_with_state(self.clone(), body_limit))
            .layer(middleware::from_fn_with_state(self.clone(), webhook_limit))
            .layer(middleware::from_fn_with_state(self.clone(), login_limit))
            .layer(middleware::from_fn_with_state(self.clone(), headers))
            .layer(middleware::from_fn_with_state(self.clone(), client_address))
            .layer(middleware::from_fn_with_state(self.clone(), firewall))
    }

    fn client(request: &Request) -> String {
        request
            .extensions()
            .get::<ClientAddress>()
            .map(|address| address.0.clone())
            .unwrap_or_else(|| "unknown".to_owned())
    }

    fn user_agent(request: &Request) -> Option<String> {
        request.headers().get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned)
    }

    /// An audit entry for a refusal of this request.
    pub(crate) fn denial(&self, request: &Request, detail: &str, principal: Option<&Principal>) -> AccessDenied {
        AccessDenied {
            path: request.uri().path().to_owned(),
            detail: detail.to_owned(),
            who: principal.map(who),
            address: Chain::client(request),
            user_agent: Chain::user_agent(request),
        }
    }
}

fn who(principal: &Principal) -> String {
    match (&principal.account, &principal.credential) {
        (Some(account), _) => account.username.clone(),
        (None, Credential::Agent { agent }) => agent.clone(),
        (None, _) => "scim".to_owned(),
    }
}

/// `Duration.toString()`: `PT5M`, `PT1H30M`, `PT0.5S` — what the Java audit text prints for a window.
fn iso_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let (hours, minutes, seconds) = (total / 3600, total % 3600 / 60, total % 60);
    if total == 0 && duration.subsec_nanos() == 0 {
        return "PT0S".to_owned();
    }
    let mut text = String::from("PT");
    if hours > 0 {
        text.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        text.push_str(&format!("{minutes}M"));
    }
    if seconds > 0 || duration.subsec_nanos() > 0 {
        if duration.subsec_nanos() == 0 {
            text.push_str(&format!("{seconds}S"));
        } else {
            let fraction = format!("{:09}", duration.subsec_nanos());
            text.push_str(&format!("{seconds}.{}S", fraction.trim_end_matches('0')));
        }
    }
    text
}

/// Whole seconds a caller is asked to wait, never less than one: a `Retry-After: 0` tells a client to retry at once.
fn seconds(wait: Duration) -> u64 {
    wait.as_secs().max(1)
}

// ── firewall ───────────────────────────────────────────────────────────────────────────────

async fn firewall(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("firewall");
    let path = request.uri().path();
    match routing::judge(path) {
        Some(refusal) => refusal.problem(path).into_response(),
        None => next.run(request).await,
    }
}

// ── client address ────────────────────────────────────────────────────────────────────────

async fn client_address(State(chain): State<Arc<Chain>>, mut request: Request, next: Next) -> Response {
    chain.visit("client-address");
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip().to_string());
    let forwarded = request.headers().get("x-forwarded-for").and_then(|value| value.to_str().ok());
    let resolved = chain.config.trusted_proxies.client_address(peer.as_deref(), forwarded);
    request.extensions_mut().insert(ClientAddress(resolved));
    next.run(request).await
}

// ── headers ───────────────────────────────────────────────────────────────────────────────

/// On every response, the interface's files included. Each is written only if the response does not carry it
/// already — a route that sets its own `Cache-Control` (the public badge) keeps it.
async fn headers(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("headers");
    let mut response = next.run(request).await;
    let map = response.headers_mut();
    let mut set = |name: &'static str, value: &'static str| {
        let name = HeaderName::from_static(name);
        if !map.contains_key(&name) {
            map.insert(name, HeaderValue::from_static(value));
        }
    };
    set("x-content-type-options", "nosniff");
    set("x-xss-protection", "0");
    // Spring's cache-control writer yields to any of the three: a response that decided its own caching keeps it.
    if !(map.contains_key(header::CACHE_CONTROL)
        || map.contains_key(header::PRAGMA)
        || map.contains_key(header::EXPIRES))
    {
        map.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache, no-store, max-age=0, must-revalidate"));
        map.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        map.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    let mut set = |name: &'static str, value: &'static str| {
        let name = HeaderName::from_static(name);
        if !map.contains_key(&name) {
            map.insert(name, HeaderValue::from_static(value));
        }
    };
    set("x-frame-options", "DENY");
    set("content-security-policy", CONTENT_SECURITY_POLICY);
    response
}

// ── the limits ────────────────────────────────────────────────────────────────────────────

const LOGIN_LIMITED: [&str; 5] = [
    "/api/v1/auth/login",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/session/exchange",
    // Not anonymous, and limited all the same: it verifies a second-factor code, so a session left open is a door to the
    // same six digits. The account's budget bounds the guesses; this bounds how fast one address can spend it.
    "/api/v1/auth/mfa/disable",
    // The same for a password: a session is not a licence to guess the one behind it.
    "/api/v1/auth/change-password",
];

const WEBHOOK_PREFIX: &str = "/api/v1/tickets/webhook/";

fn is_post(request: &Request) -> bool {
    request.method() == http::Method::POST
}

async fn login_limit(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("login-limit");
    if is_post(&request) && LOGIN_LIMITED.contains(&routed_path(request.uri().path()).as_str()) {
        let key = client_bucket(&Chain::client(&request));
        let taken = chain.login.consume(&key);
        if !taken.consumed {
            let retry = seconds(taken.wait);
            // `retryAfterSeconds` in the body as well as in the header: the sign-in screen reads it there to say how
            // long to wait, and no limiter had ever sent it.
            return Problem::chain(
                StatusCode::TOO_MANY_REQUESTS,
                format!("Rate limit exceeded. Too many login attempts. Please try again in {retry} seconds."),
            )
            .at(request.uri().path())
            .with("retryAfterSeconds", retry)
            .header("Retry-After", retry.to_string())
            .header("X-Rate-Limit-Retry-After-Seconds", retry.to_string())
            .into_response();
        }
    }
    next.run(request).await
}

async fn webhook_limit(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("webhook-limit");
    if is_post(&request) && routed_path(request.uri().path()).starts_with(WEBHOOK_PREFIX) {
        let address = client_bucket(&Chain::client(&request));
        let taken = chain.webhook.consume(&address);
        if !taken.consumed {
            return webhook_refusal(request.uri().path(), taken.wait);
        }
        if let Some(shared) = &chain.shared_webhook
            && let Err(wait) = shared.hit(&address, chain.config.webhook_requests, chain.config.webhook_window).await
        {
            return webhook_refusal(request.uri().path(), wait);
        }
    }
    next.run(request).await
}

fn webhook_refusal(path: &str, wait: Duration) -> Response {
    let retry = seconds(wait);
    Problem::chain(
        StatusCode::TOO_MANY_REQUESTS,
        format!("Too many webhook deliveries from this address. Try again in {retry} seconds."),
    )
    .at(path)
    .with("retryAfterSeconds", retry)
    .header("Retry-After", retry.to_string())
    .into_response()
}

/// A declared length over the ceiling is refused before a byte is read; anything else is counted as it is read.
async fn body_limit(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("body-limit");
    let ceiling = chain.config.body_limits.ceiling(request.method().as_str(), request.uri().path());
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if declared.is_some_and(|length| length > ceiling) {
        return Problem::chain(StatusCode::PAYLOAD_TOO_LARGE, too_large_detail(ceiling))
            .at(request.uri().path())
            .into_response();
    }
    let (parts, body) = request.into_parts();
    next.run(Request::from_parts(parts, Counting::wrap(body, ceiling))).await
}

/// Whether the request carries a credential the bearer layer will try: an `Authorization: Bearer …`, or — with no
/// `Authorization` at all — a non-blank `X-API-Key`.
fn carries_bearer(request: &Request) -> bool {
    match request.headers().get(header::AUTHORIZATION) {
        Some(value) => value.as_bytes().get(..7).is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"bearer ")),
        None => request
            .headers()
            .get(API_KEY_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.trim().is_empty()),
    }
}

/// What the bearer layer tells the one outside it: whether the credential resolved.
#[derive(Clone, Copy, Debug)]
struct Resolved(bool);

/// A ceiling on **refused** bearer tokens per address. Only failures count, so an estate of well-configured agents
/// leaves the map empty and pays one hash lookup.
async fn bearer_limit(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("bearer-limit");
    if !carries_bearer(&request) {
        return next.run(request).await;
    }
    let address = Chain::client(&request);
    let key = client_bucket(&address);
    // Read without creating: a bucket appears the first time an address fails.
    if chain.bearer.available(&key) == Some(0) {
        let retry = seconds(chain.bearer.wait(&key));
        return Problem::chain(
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many refused credentials from this address. Try again in {retry} seconds."),
        )
        .at(request.uri().path())
        .with("retryAfterSeconds", retry)
        .header("Retry-After", retry.to_string())
        .into_response();
    }
    let denial = chain.denial(
        &request,
        &format!(
            "{} bearer tokens refused from this address within {}. Further credentialed requests from it are answered 429 until the window refills.",
            chain.config.bearer_failures,
            iso_duration(chain.config.bearer_window)
        ),
        None,
    );
    let response = next.run(request).await;
    if response.extensions().get::<Resolved>().is_some_and(|resolved| !resolved.0) {
        let taken = chain.bearer.consume(&key);
        if taken.consumed && taken.remaining_tokens == 0 {
            chain.audit.bearer_throttled(AccessDenied { address, ..denial });
        }
    }
    response
}

// ── the bearer ────────────────────────────────────────────────────────────────────────────

/// `Authorization: Bearer <token>`, the scheme matched without case, the token everything after the first run of
/// whitespace.
fn bearer_token(header_value: &str) -> Option<&str> {
    let mut parts = header_value.trim().splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim_start();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

fn is_scim_path(path: &str) -> bool {
    path == "/scim" || path.starts_with("/scim/")
}

/// Resolves the credential, if any, into the principal the rest of the chain and the handlers read.
///
/// **The SCIM token is a principal on `/scim` and nowhere else.** It is held by the identity provider — a third
/// system, with its own operators and its own breaches — and it used to authenticate as an unrestricted administrator on
/// every route. Elsewhere it is not recognised and falls through to the key lookup like any unknown bearer.
async fn bearer(State(chain): State<Arc<Chain>>, mut request: Request, next: Next) -> Response {
    chain.visit("bearer");
    let header_value =
        request.headers().get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).map(str::to_owned);
    let api_key_header = request.headers().get(API_KEY_HEADER).and_then(|value| value.to_str().ok()).map(str::to_owned);
    let path = request.uri().path().to_owned();
    let mut principal = None;
    if let Some(token) = header_value.as_deref().and_then(bearer_token) {
        principal = chain.credentials.session(token).await;
        if principal.is_none() && is_scim_path(&path) && chain.credentials.scim(token).await {
            principal = Some(Principal::scim());
        }
        if principal.is_none() {
            principal = chain.credentials.api_key(token).await;
        }
    }
    if principal.is_none() && header_value.is_none() {
        // `X-API-Key`, the alias the OpenAPI document has always announced. A key only: a session token or the SCIM
        // token presented there is not looked at.
        if let Some(key) = api_key_header.as_deref().filter(|value| !value.trim().is_empty()) {
            principal = chain.credentials.api_key(key).await.filter(|found| !found.is_session());
        }
    }
    let resolved = principal.is_some();
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }
    let mut response = next.run(request).await;
    response.extensions_mut().insert(Resolved(resolved));
    response
}

// ── access ────────────────────────────────────────────────────────────────────────────────

/// `authorizeHttpRequests`: what may be reached with no credential, what needs one, and the administrator's session
/// for the actuator.
async fn access(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("access");
    let path = request.uri().path().to_owned();
    let principal = request.extensions().get::<Principal>().cloned();
    match access::gate(request.method().as_str(), &path, chain.config.anonymous_api_docs) {
        Gate::Open => {}
        Gate::Authenticated => {
            if principal.is_none() {
                return unauthenticated(&path).into_response();
            }
        }
        Gate::AdministratorSession => {
            let Some(principal) = principal else { return unauthenticated(&path).into_response() };
            let administrator = principal.is_session()
                && !principal.must_change_password()
                && principal.role().is_some_and(|role| role.is_administrative());
            if !administrator {
                return refuse_denied(&chain, &request, Some(&principal));
            }
        }
    }
    next.run(request).await
}

/// 403, audited. The sentence names no role: a list of the roles a route admits is a map of whose credentials to go after.
pub(crate) fn refuse_denied(chain: &Chain, request: &Request, principal: Option<&Principal>) -> Response {
    chain.audit.access_denied(chain.denial(request, "Access denied: Access Denied", principal));
    Problem::chain(StatusCode::FORBIDDEN, FORBIDDEN).at(request.uri().path()).into_response()
}

// ── problems ──────────────────────────────────────────────────────────────────────────────

/// A problem a handler raised has no `instance` yet: Spring fills it in from the request, and so does this.
async fn problems(State(chain): State<Arc<Chain>>, request: Request, next: Next) -> Response {
    chain.visit("problems");
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    match response.extensions().get::<Problem>() {
        Some(problem) if problem.instance().is_none() => problem.clone().at(path).into_response(),
        _ => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_is_printed_as_java_prints_a_duration() {
        assert_eq!(iso_duration(Duration::from_secs(300)), "PT5M");
        assert_eq!(iso_duration(Duration::from_secs(60)), "PT1M");
        assert_eq!(iso_duration(Duration::from_secs(5400)), "PT1H30M");
        assert_eq!(iso_duration(Duration::from_secs(45)), "PT45S");
        assert_eq!(iso_duration(Duration::from_millis(500)), "PT0.5S");
        assert_eq!(iso_duration(Duration::ZERO), "PT0S");
    }

    #[test]
    fn a_caller_is_never_told_to_wait_zero_seconds() {
        assert_eq!(seconds(Duration::from_millis(400)), 1);
        assert_eq!(seconds(Duration::from_millis(1900)), 1);
        assert_eq!(seconds(Duration::from_secs(6)), 6);
    }

    #[test]
    fn the_bearer_scheme_and_its_token_are_read_as_the_java_filter_reads_them() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bEaReR   abc"), Some("abc"));
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer "), None);
    }
}
