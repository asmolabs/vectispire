//! The axum side: declaring routes as they are registered, asking a router whether it answers them,
//! and replaying goldens against one.

use std::collections::BTreeSet;

use axum::Router;
use axum::body::Body as AxumBody;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::routing::MethodRouter;
use tower::ServiceExt;

use crate::document::{Document, fill_parameters};
use crate::finding::Finding;
use crate::golden::{Body, Golden, Request, Response, Server, ServerError};
use crate::json::Json;
use crate::routes::{Allowlist, RouteDecl, RouteSource};

/// The header a router built for [`probe`] answers with when no route matched — a status alone
/// cannot say it, since a handler answers `404` for a project that does not exist.
pub const NO_ROUTE_HEADER: &str = "x-cp-contract-no-route";

/// How much of an answer a replay reads: the largest body the control plane serves is an export.
const BODY_LIMIT: usize = 256 * 1024 * 1024;

/// A router that records what it registers.
///
/// axum cannot list its routes, so the routes are written down at the one place they are added:
/// `route` takes the declaration and the method router together. That the two agree — that the
/// method router answers the method declared — is what [`probe`] checks.
#[derive(Default, Debug)]
pub struct RecordingRouter {
    router: Router,
    declared: Vec<RouteDecl>,
}

impl RecordingRouter {
    #[must_use]
    pub fn new() -> RecordingRouter {
        RecordingRouter::default()
    }

    /// Registers `handlers` at the declaration's path and records the declaration.
    #[must_use]
    pub fn route(mut self, declaration: RouteDecl, handlers: MethodRouter) -> RecordingRouter {
        self.router = self.router.route(&declaration.path, handlers);
        self.declared.push(declaration);
        self
    }

    /// The router as registered.
    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

impl RouteSource for RecordingRouter {
    fn routes(&self) -> Vec<RouteDecl> {
        self.declared.clone()
    }
}

const METHODS: [&str; 5] = ["GET", "POST", "PUT", "DELETE", "PATCH"];

/// Sends every documented request to `router` and reports what it does not answer.
///
/// The router is probed **as built**: no credential, no body, the path's parameters filled with `1`.
/// Whatever the handlers do with that request is the test's to make harmless — build the router with
/// test doubles — and an authentication layer in front of the routes would answer for them, so
/// probe the router without one (the route builder's layers are tested where they are written).
/// A route answering anything but the sentinel is served; `405` or a sentinel on the wrong method
/// is `MethodNotServed`; the sentinel everywhere on the path is `NotServed`. A route on the
/// allowlist must *not* be served.
pub async fn probe(router: &Router, document: &Document, allowlist: &Allowlist) -> Vec<Finding> {
    let probing = router.clone().fallback(|| async { (StatusCode::NOT_FOUND, [(NO_ROUTE_HEADER, "1")]) });
    let mut findings = Vec::new();
    let mut routed_paths: BTreeSet<String> = BTreeSet::new();

    for operation in document.operations() {
        let served = answers(&probing, &operation.method, &operation.path).await;
        let listed = allowlist.entries().contains(&(operation.method.clone(), operation.path.clone()));
        match (served, listed) {
            (true, true) => findings
                .push(Finding::AllowlistedButServed { method: operation.method.clone(), path: operation.path.clone() }),
            (true, false) => {
                routed_paths.insert(operation.path.clone());
            }
            (false, true) => {}
            (false, false) => {
                let mut path_exists = routed_paths.contains(&operation.path);
                if !path_exists {
                    for other in METHODS.iter().filter(|other| **other != operation.method) {
                        if answers(&probing, other, &operation.path).await {
                            path_exists = true;
                            break;
                        }
                    }
                }
                findings.push(if path_exists {
                    Finding::MethodNotServed { method: operation.method.clone(), path: operation.path.clone() }
                } else {
                    Finding::NotServed { method: operation.method.clone(), path: operation.path.clone() }
                });
            }
        }
    }
    findings
}

/// Whether the router has a handler for the method on the path: it answered, and not with the
/// sentinel nor with `405`.
async fn answers(router: &Router, method: &str, template: &str) -> bool {
    let concrete = fill_parameters(template, "1");
    let Ok(method) = Method::from_bytes(method.as_bytes()) else {
        return false;
    };
    let Ok(request) = axum::http::Request::builder().method(method).uri(&concrete).body(AxumBody::empty()) else {
        return false;
    };
    match router.clone().oneshot(request).await {
        Ok(response) => {
            !response.headers().contains_key(NO_ROUTE_HEADER) && response.status() != StatusCode::METHOD_NOT_ALLOWED
        }
        Err(never) => match never {},
    }
}

type Seeder = Box<dyn FnMut(&Golden) -> Result<(), String> + Send>;
type Dumper = Box<dyn FnMut(&[String]) -> Result<Option<Json>, String> + Send>;

/// A router replayed in process: no socket, the whole stack of layers.
#[derive(Default)]
pub struct AxumServer {
    router: Router,
    seed: Option<Seeder>,
    dump: Option<Dumper>,
}

impl std::fmt::Debug for AxumServer {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AxumServer").finish_non_exhaustive()
    }
}

impl AxumServer {
    #[must_use]
    pub fn new(router: Router) -> AxumServer {
        AxumServer { router, seed: None, dump: None }
    }

    /// How a golden's `db.before` rows are put in place.
    #[must_use]
    pub fn seeding(mut self, seed: impl FnMut(&Golden) -> Result<(), String> + Send + 'static) -> AxumServer {
        self.seed = Some(Box::new(seed));
        self
    }

    /// How the rows a request touched are read back.
    #[must_use]
    pub fn dumping(
        mut self,
        dump: impl FnMut(&[String]) -> Result<Option<Json>, String> + Send + 'static,
    ) -> AxumServer {
        self.dump = Some(Box::new(dump));
        self
    }
}

impl Server for AxumServer {
    async fn prepare(&mut self, golden: &Golden) -> Result<(), ServerError> {
        match &mut self.seed {
            Some(seed) => seed(golden).map_err(ServerError),
            None => Ok(()),
        }
    }

    async fn send(&mut self, request: &Request) -> Result<Response, ServerError> {
        let mut builder = axum::http::Request::builder().method(request.method.as_str()).uri(request.target());
        for (name, value) in &request.headers {
            let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) else {
                return Err(ServerError(format!("the recorded header {name:?} cannot be sent")));
            };
            builder = builder.header(name, value);
        }
        let body = request.body.as_ref().map_or_else(AxumBody::empty, |body| AxumBody::from(body.to_text()));
        let built = builder
            .body(body)
            .map_err(|error| ServerError(format!("the recorded request is not a request: {error}")))?;
        let response = match self.router.clone().oneshot(built).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
            .collect();
        let bytes = axum::body::to_bytes(response.into_body(), BODY_LIMIT)
            .await
            .map_err(|error| ServerError(format!("the answer's body could not be read: {error}")))?;
        Ok(into_response(status, headers, &bytes))
    }

    async fn db_effects(&mut self, tables: &[String]) -> Result<Option<Json>, ServerError> {
        match &mut self.dump {
            Some(dump) => dump(tables).map_err(ServerError),
            None => Ok(None),
        }
    }
}

/// A server reached over HTTP — the control plane as it ships.
pub struct HttpServer {
    client: reqwest::Client,
    base: String,
    seed: Option<Seeder>,
    dump: Option<Dumper>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("HttpServer").field("base", &self.base).finish_non_exhaustive()
    }
}

impl HttpServer {
    /// A server at `base`, `http://127.0.0.1:3180` for instance. No redirect is followed: a replay
    /// reports the `302`, it does not chase it.
    pub fn new(base: &str) -> Result<HttpServer, ServerError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ServerError(format!("no HTTP client: {error}")))?;
        Ok(HttpServer { client, base: base.trim_end_matches('/').to_owned(), seed: None, dump: None })
    }

    /// How a golden's `db.before` rows are put in place.
    #[must_use]
    pub fn seeding(mut self, seed: impl FnMut(&Golden) -> Result<(), String> + Send + 'static) -> HttpServer {
        self.seed = Some(Box::new(seed));
        self
    }

    /// How the rows a request touched are read back.
    #[must_use]
    pub fn dumping(
        mut self,
        dump: impl FnMut(&[String]) -> Result<Option<Json>, String> + Send + 'static,
    ) -> HttpServer {
        self.dump = Some(Box::new(dump));
        self
    }
}

impl Server for HttpServer {
    async fn prepare(&mut self, golden: &Golden) -> Result<(), ServerError> {
        match &mut self.seed {
            Some(seed) => seed(golden).map_err(ServerError),
            None => Ok(()),
        }
    }

    async fn send(&mut self, request: &Request) -> Result<Response, ServerError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| ServerError(format!("not a method: {error}")))?;
        let mut builder = self.client.request(method, format!("{}{}", self.base, request.target()));
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.to_text());
        }
        let response = builder
            .send()
            .await
            .map_err(|error| ServerError(format!("{} {}: {error}", request.method, request.path)))?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
            .collect();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| ServerError(format!("the answer's body could not be read: {error}")))?;
        Ok(into_response(status, headers, &bytes))
    }

    async fn db_effects(&mut self, tables: &[String]) -> Result<Option<Json>, ServerError> {
        match &mut self.dump {
            Some(dump) => dump(tables).map_err(ServerError),
            None => Ok(None),
        }
    }
}

/// An answer's body as a golden holds one: JSON read with its order kept, anything else as text.
fn into_response(status: u16, headers: Vec<(String, String)>, bytes: &[u8]) -> Response {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let json_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, value)| value.contains("json"));
    let body = if text.is_empty() {
        None
    } else if json_type {
        Some(Json::parse(&text).map_or(Body::Text(text), Body::Json))
    } else {
        Some(Body::Text(text))
    };
    Response { status, headers, body }
}
