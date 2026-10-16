//! The route builder: **a route that does not say what it requires, and how it handles visibility, does not
//! compile.**
//!
//! AGENTS.md calls "a role marker is not authorization" the mistake made most often here: twenty-three routes carried a
//! marker, passed the route-annotation test, and served other accounts' repositories — and four manual sweeps did not
//! converge, the twenty-first hole appearing hours after the twentieth was closed. The Java answer is a test that walks
//! the routes (`AuthorizationCoverageTest`). This is the stronger one, where Rust can give it: the only way to turn a
//! route description into a route is [`RouteSpec::handler`], and that exists only once both questions are answered.
//!
//! ```text
//! Route::get("/api/v1/repositories")      RouteSpec<Unset, Unset>
//!     .requires(Access::Account)          RouteSpec<Declared, Unset>     which marker
//!     .scoped()                           RouteSpec<Declared, Declared>  the handler gets a `Scoped<V>`
//!     .handler(list)                      RouteEntry                     (no `.handler` before this point)
//! ```
//!
//! `names_no_target()` is the other answer: this route names no target (a user list, a setting). It is a *declaration*
//! the table keeps, so a review — and the port of `AuthorizationCoverageTest` — can list every route that said so.
//! The refusal a scoped handler owes is [`require_visible`]: a 404, **never** a 403, and the same 404 for a row that
//! is absent and for one the caller may not see, or a refusal confirms the thing exists.

use crate::access::Access;
use crate::chain::{Chain, refuse_denied, unauthenticated};
use crate::credentials::BoxFuture;
use crate::extract::Scoped;
use crate::interface::Interface;
use crate::principal::{ApiKeyScope, Credential, Principal};
use crate::problem::Problem;
use axum::Router;
use axum::extract::{Request, State};
use axum::handler::Handler;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter, on};
use http::{Method, StatusCode};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

/// A question not yet answered.
#[derive(Clone, Copy, Debug)]
pub struct Unset;
/// A question answered.
#[derive(Clone, Copy, Debug)]
pub struct Declared;

/// How a route handles visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// The route names no target: nothing it returns depends on which targets the caller may see.
    NamesNoTarget,
    /// The route names a target or aggregates over them: the gate resolves the caller's visibility and the handler reads
    /// it as [`Scoped`]. Applying it in the query — and refusing through [`require_visible`] — is the handler's.
    Scoped,
}

/// Resolves what a principal may see, for the routes that declared `.scoped()`. Phase 1's `VisibilityService`.
pub trait VisibilityOf<V>: Send + Sync {
    fn of<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, V>;
}

/// For an application with no scoped route.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVisibility;

impl VisibilityOf<()> for NoVisibility {
    fn of<'a>(&'a self, _principal: &'a Principal) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// A route being described. Its two type parameters say which questions it has answered.
#[derive(Debug)]
pub struct RouteSpec<A, S> {
    method: Method,
    path: String,
    access: Option<Access>,
    visibility: Option<Visibility>,
    accepts_api_key: Option<ApiKeyScope>,
    allows_pending_password_change: bool,
    state: PhantomData<(A, S)>,
}

/// The starting points.
#[derive(Debug)]
pub struct Route;

impl Route {
    pub fn get(path: &str) -> RouteSpec<Unset, Unset> {
        RouteSpec::new(Method::GET, path)
    }

    pub fn post(path: &str) -> RouteSpec<Unset, Unset> {
        RouteSpec::new(Method::POST, path)
    }

    pub fn put(path: &str) -> RouteSpec<Unset, Unset> {
        RouteSpec::new(Method::PUT, path)
    }

    pub fn patch(path: &str) -> RouteSpec<Unset, Unset> {
        RouteSpec::new(Method::PATCH, path)
    }

    pub fn delete(path: &str) -> RouteSpec<Unset, Unset> {
        RouteSpec::new(Method::DELETE, path)
    }
}

impl RouteSpec<Unset, Unset> {
    fn new(method: Method, path: &str) -> RouteSpec<Unset, Unset> {
        RouteSpec {
            method,
            path: path.to_owned(),
            access: None,
            visibility: None,
            accepts_api_key: None,
            allows_pending_password_change: false,
            state: PhantomData,
        }
    }
}

impl<S> RouteSpec<Unset, S> {
    /// The role marker. **Required**: `.handler` does not exist without it.
    pub fn requires(self, access: Access) -> RouteSpec<Declared, S> {
        RouteSpec {
            method: self.method,
            path: self.path,
            access: Some(access),
            visibility: self.visibility,
            accepts_api_key: self.accepts_api_key,
            allows_pending_password_change: self.allows_pending_password_change,
            state: PhantomData,
        }
    }
}

impl<A> RouteSpec<A, Unset> {
    /// This route names no target. **Required**, one way or the other: `.handler` does not exist without it.
    pub fn names_no_target(self) -> RouteSpec<A, Declared> {
        self.with_visibility(Visibility::NamesNoTarget)
    }

    /// This route names a target or aggregates over them: the caller's visibility is resolved before the handler runs.
    pub fn scoped(self) -> RouteSpec<A, Declared> {
        self.with_visibility(Visibility::Scoped)
    }

    fn with_visibility(self, visibility: Visibility) -> RouteSpec<A, Declared> {
        RouteSpec {
            method: self.method,
            path: self.path,
            access: self.access,
            visibility: Some(visibility),
            accepts_api_key: self.accepts_api_key,
            allows_pending_password_change: self.allows_pending_password_change,
            state: PhantomData,
        }
    }
}

impl<A, S> RouteSpec<A, S> {
    /// `@AcceptsApiKey(scope)` — **opt-in, never the default**: an integration key reaches only the routes that carry
    /// this, whatever its owner's role, and only with the scope.
    pub fn accepts_api_key(mut self, scope: ApiKeyScope) -> RouteSpec<A, S> {
        self.accepts_api_key = Some(scope);
        self
    }

    /// `@PasswordChangeGate` — reachable while the account still owes a password change (sign out, change it, who am I).
    pub fn allows_pending_password_change(mut self) -> RouteSpec<A, S> {
        self.allows_pending_password_change = true;
        self
    }
}

impl RouteSpec<Declared, Declared> {
    /// The handler. Exists only for a route that has answered both questions.
    pub fn handler<H, T>(self, handler: H) -> RouteEntry
    where
        H: Handler<T, ()> + Clone + Send + Sync + 'static,
        T: 'static,
    {
        let filter = MethodFilter::try_from(self.method.clone()).unwrap_or(MethodFilter::GET);
        RouteEntry {
            decl: RouteDecl {
                method: self.method.as_str().to_owned(),
                path: self.path,
                access: self.access.unwrap_or(Access::Account),
                visibility: self.visibility.unwrap_or(Visibility::Scoped),
                accepts_api_key: self.accepts_api_key,
                allows_pending_password_change: self.allows_pending_password_change,
            },
            method_router: on(filter, handler),
        }
    }
}

/// What a registered route declared — the table a coverage test walks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDecl {
    pub method: String,
    pub path: String,
    pub access: Access,
    pub visibility: Visibility,
    pub accepts_api_key: Option<ApiKeyScope>,
    pub allows_pending_password_change: bool,
}

/// A route with its handler, ready to be added to [`Routes`].
#[derive(Debug)]
pub struct RouteEntry {
    decl: RouteDecl,
    method_router: MethodRouter<()>,
}

impl RouteEntry {
    pub fn decl(&self) -> &RouteDecl {
        &self.decl
    }
}

/// Two entries for one method and path.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{method} {path} is registered twice")]
pub struct DuplicateRoute {
    pub method: String,
    pub path: String,
}

/// The control plane's routes, with what each declared.
pub struct Routes<V> {
    entries: Vec<RouteEntry>,
    visibility: Arc<dyn VisibilityOf<V>>,
}

impl<V> std::fmt::Debug for Routes<V> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Routes").field("routes", &self.entries.len()).finish()
    }
}

impl<V: Clone + Send + Sync + 'static> Routes<V> {
    pub fn new(visibility: impl VisibilityOf<V> + 'static) -> Routes<V> {
        Routes { entries: Vec::new(), visibility: Arc::new(visibility) }
    }

    pub fn route(mut self, entry: RouteEntry) -> Routes<V> {
        self.entries.push(entry);
        self
    }

    /// Every route and what it declared — the input of the port of `AuthorizationCoverageTest` and `RouteAuthorizationTest`.
    pub fn table(&self) -> Vec<RouteDecl> {
        self.entries.iter().map(|entry| entry.decl.clone()).collect()
    }

    /// The router, wrapped in the chain, with `interface` — the Angular build — served from the same origin.
    pub fn build(self, chain: &Arc<Chain>, interface: Option<Interface>) -> Result<Router, DuplicateRoute> {
        let mut seen = BTreeMap::new();
        let mut by_path: BTreeMap<String, Vec<RouteEntry>> = BTreeMap::new();
        for entry in self.entries {
            if seen.insert((entry.decl.method.clone(), entry.decl.path.clone()), ()).is_some() {
                return Err(DuplicateRoute { method: entry.decl.method, path: entry.decl.path });
            }
            by_path.entry(entry.decl.path.clone()).or_default().push(entry);
        }
        let mut router = Router::new();
        for (path, entries) in by_path {
            let mut allowed: Vec<String> = entries.iter().map(|entry| entry.decl.method.clone()).collect();
            allowed.sort();
            let mut merged: Option<MethodRouter<()>> = None;
            for entry in entries {
                let gate = Arc::new(RouteGate::new(chain, &entry.decl, self.visibility.clone()));
                let gated = entry.method_router.route_layer(middleware::from_fn_with_state(gate, route_gate));
                merged = Some(match merged {
                    None => gated,
                    Some(existing) => existing.merge(gated),
                });
            }
            if let Some(merged) = merged {
                // Another method on this path: Spring answers 405 with an `Allow` header naming the ones it has.
                let allow = allowed.join(", ");
                let merged = merged.fallback(move |method: Method| {
                    let allow = allow.clone();
                    async move {
                        Problem::handler(StatusCode::METHOD_NOT_ALLOWED, format!("Method '{method}' is not supported."))
                            .header("Allow", allow)
                    }
                });
                router = router.route(&path, merged);
            }
        }
        let router = match interface {
            Some(interface) => router.fallback_service(interface.into_service()),
            None => router.fallback(not_found),
        };
        Ok(chain.apply(router))
    }
}

/// An unmapped path, in Vectispire's words — not Spring's "No static resource api/v1/…".
pub(crate) async fn not_found() -> Problem {
    Problem::handler(StatusCode::NOT_FOUND, "Nothing is served at this path.")
}

/// A row the caller may see, or the one 404 an absent row and an invisible one share.
///
/// `visible` is the caller's visibility applied to the row; an absent row never reaches it. **The two refusals are the
/// same bytes** — a test pins it — or the refusal would confirm that the thing exists.
pub fn require_visible<T>(row: Option<T>, visible: impl FnOnce(&T) -> bool, message: &str) -> Result<T, Problem> {
    match row {
        Some(row) if visible(&row) => Ok(row),
        _ => Err(Problem::handler(StatusCode::NOT_FOUND, message)),
    }
}

// ── the gate every route runs ─────────────────────────────────────────────────────────────

struct RouteGate {
    chain: Arc<Chain>,
    access: Access,
    accepts_api_key: Option<ApiKeyScope>,
    allows_pending_password_change: bool,
    scope: Option<ScopeResolver>,
}

type ScopeInsert = Box<dyn FnOnce(&mut http::Extensions) + Send>;
type ScopeResolver = Arc<dyn Fn(Principal) -> BoxFuture<'static, ScopeInsert> + Send + Sync>;

impl RouteGate {
    fn new<V: Clone + Send + Sync + 'static>(
        chain: &Arc<Chain>,
        decl: &RouteDecl,
        visibility: Arc<dyn VisibilityOf<V>>,
    ) -> RouteGate {
        let scope: Option<ScopeResolver> = (decl.visibility == Visibility::Scoped).then(|| {
            let resolver: ScopeResolver = Arc::new(move |principal: Principal| {
                let visibility = visibility.clone();
                Box::pin(async move {
                    let value = visibility.of(&principal).await;
                    Box::new(move |extensions: &mut http::Extensions| {
                        extensions.insert(Scoped(value));
                    }) as ScopeInsert
                })
            });
            resolver
        });
        RouteGate {
            chain: chain.clone(),
            access: decl.access,
            accepts_api_key: decl.accepts_api_key,
            allows_pending_password_change: decl.allows_pending_password_change,
            scope,
        }
    }
}

const PASSWORD_CHANGE: &str = "A password change is required before any other action.";
const AGENT_KEY_ABSENT: &str = "API key absent, invalid, or without the \"agent\" scope.";

/// The part of the chain that needs the route: the Java MVC interceptors (`PasswordChangeInterceptor`, then
/// `CredentialConfinement`) and the method security of the marker. It runs for a matched route only — an unmapped path
/// or a wrong method is answered before it, as Spring answers it before an interceptor.
async fn route_gate(State(gate): State<Arc<RouteGate>>, mut request: Request, next: Next) -> Response {
    let chain = &gate.chain;
    let principal = request.extensions().get::<Principal>().cloned();

    // 1. A password change owed. 403 and not 401: the token is good and the server knows who this is; 401 would send the
    //    client back to sign in, which it has already done — and would do again, in a loop.
    chain.visit("password-change");
    if principal.as_ref().is_some_and(Principal::must_change_password) && !gate.allows_pending_password_change {
        return Problem::handler(StatusCode::FORBIDDEN, PASSWORD_CHANGE).into_response();
    }

    // 2. What this kind of credential may reach at all. An agent's key reaches the agent routes; an integration key,
    //    only the routes that accept one, with the scope, within its budget.
    chain.visit("credential-confinement");
    if let Some(principal) = &principal {
        match &principal.credential {
            Credential::Agent { .. } if gate.access != Access::AgentKey => {
                return Problem::handler(StatusCode::FORBIDDEN, "This route does not accept an agent key.")
                    .into_response();
            }
            Credential::Integration { key_id, scopes } => {
                let Some(needed) = gate.accepts_api_key else {
                    return Problem::handler(StatusCode::FORBIDDEN, "This route does not accept an API key.")
                        .into_response();
                };
                if !scopes.contains(&needed) {
                    return Problem::handler(
                        StatusCode::FORBIDDEN,
                        format!("This API key lacks the {} scope.", needed.wire_name()),
                    )
                    .into_response();
                }
                let taken = chain.keys.consume(key_id);
                if !taken.consumed {
                    let seconds = taken.wait.as_secs().max(1);
                    return Problem::handler(
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("This API key has made too many requests. Try again in {seconds} seconds."),
                    )
                    .with("retryAfterSeconds", seconds)
                    .header("Retry-After", seconds.to_string())
                    .into_response();
                }
            }
            _ => {}
        }
    }

    // 3. The marker.
    chain.visit("role");
    match gate.access {
        Access::Anonymous => {}
        Access::AgentKey => {
            if !principal.as_ref().is_some_and(Principal::is_agent) {
                return Problem::handler(StatusCode::UNAUTHORIZED, AGENT_KEY_ABSENT).into_response();
            }
        }
        Access::Account => {
            if principal.is_none() {
                return unauthenticated(request.uri().path()).into_response();
            }
        }
        other => match &principal {
            None => return unauthenticated(request.uri().path()).into_response(),
            Some(principal) => {
                if !other.admits(principal.role()) {
                    return refuse_denied(chain, &request, Some(principal));
                }
            }
        },
    }

    // 4. A scoped route's visibility, resolved for the principal and the credential's restriction.
    if let (Some(scope), Some(principal)) = (&gate.scope, principal) {
        let insert = scope(principal).await;
        insert(request.extensions_mut());
    }
    next.run(request).await
}
