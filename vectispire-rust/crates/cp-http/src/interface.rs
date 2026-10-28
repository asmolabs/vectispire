//! The Angular build, served from the same origin as the API — so `connect-src 'self'` stays true and the interface
//! needs no second workload (decision 0038).
//!
//! **What the Java side does, and this reproduces:**
//!
//! * a file the build contains is served as a static resource: its media type from the extension, `Last-Modified`,
//!   `Accept-Ranges: bytes`, and — like every response — the chain's no-cache headers and the CSP;
//! * `/` and the SPA's deep links (`SpaForwarding`: one dotless segment, or two or three whose first is not `api`,
//!   `actuator` or `scim`, none with a dot) are answered with `index.html` as `text/html;charset=UTF-8` and a
//!   `Content-Language` — the headers a *forward* gets, which differ from a direct request for `/index.html`
//!   (`text/html`, no language);
//! * anything else is the 404 problem "Nothing is served at this path.", so an unmapped API path stays a 404 the caller can
//!   act on instead of an HTML page, and a lost `.js` stays a 404 and not a document the browser reports as a syntax error.
//!
//! **Not reproduced:** `Range` on the forwarded `index.html` (the build's files are served by `tower-http`, which does
//! honour it). Nothing in the interface asks for a range of a 1 KB page.

use crate::problem::Problem;
use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode, header};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;
use tower::ServiceExt;
use tower_http::services::ServeDir;

/// The `Content-Language` a forwarded page carries: the JVM's default locale on the Java side, which the Java container's
/// image fixes to `en-US`. Pinned here rather than read from the environment.
pub const CONTENT_LANGUAGE: &str = "en-US";

/// The interface's files and its `index.html`, read once at start-up.
#[derive(Clone, Debug)]
pub struct Interface {
    root: Arc<PathBuf>,
    index: Bytes,
    modified: HeaderValue,
}

impl Interface {
    /// `None` when the directory holds no `index.html`: with no interface there is nothing to serve, which is the Java
    /// side's `@ConditionalOnResource("classpath:static/index.html")`.
    pub fn load(root: &Path) -> Option<Interface> {
        let index_path = root.join("index.html");
        let index = std::fs::read(&index_path).ok()?;
        let modified = std::fs::metadata(&index_path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| HeaderValue::from_str(&httpdate::fmt_http_date(time)).ok())
            .unwrap_or_else(|| HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"));
        Some(Interface { root: Arc::new(root.to_path_buf()), index: Bytes::from(index), modified })
    }

    pub(crate) fn into_service(self) -> InterfaceService {
        InterfaceService { interface: self }
    }

    fn index_response(&self) -> Response {
        let mut response = Response::new(Body::from(self.index.clone()));
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html;charset=UTF-8"));
        headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static(CONTENT_LANGUAGE));
        headers.insert(header::LAST_MODIFIED, self.modified.clone());
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        response
    }
}

/// `SpaForwarding`'s three patterns. `path` is the request path as received.
pub fn is_forwarded(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else { return false };
    if rest.is_empty() {
        return true;
    }
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty() || segment.contains('.')) {
        return false;
    }
    match segments.len() {
        1 => true,
        2 | 3 => !matches!(segments.first().copied(), Some("api" | "actuator" | "scim")),
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InterfaceService {
    interface: Interface,
}

impl Service<Request> for InterfaceService {
    type Response = Response;
    type Error = Infallible;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let interface = self.interface.clone();
        Box::pin(async move { Ok(serve(&interface, request).await) })
    }
}

async fn serve(interface: &Interface, request: Request) -> Response {
    let readable = matches!(*request.method(), Method::GET | Method::HEAD);
    if !readable {
        return Problem::handler(StatusCode::NOT_FOUND, "Nothing is served at this path.").into_response();
    }
    let path = request.uri().path().to_owned();
    let served = ServeDir::new(interface.root.as_path()).append_index_html_on_directories(false).oneshot(request).await;
    match served {
        Ok(response) if response.status() != StatusCode::NOT_FOUND => response.map(Body::new),
        _ if is_forwarded(&path) => interface.index_response(),
        _ => Problem::handler(StatusCode::NOT_FOUND, "Nothing is served at this path.").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_forwards_what_spa_forwarding_forwards() {
        for path in ["/", "/projects", "/api", "/actuator", "/projects/1", "/projects/1/checklist", "/a/b/c"] {
            assert!(is_forwarded(path), "{path}");
        }
        for path in [
            "/a/b/c/d",
            "/api/v1",
            "/api/v1/x",
            "/actuator/metrics",
            "/scim/v2/Users",
            "/a.b",
            "/a/b.c",
            "/projects/",
            "/missing.png",
        ] {
            assert!(!is_forwarded(path), "{path}");
        }
    }

    #[test]
    fn no_index_html_means_no_interface() {
        let empty = tempfile::tempdir().expect("a directory");
        assert!(Interface::load(empty.path()).is_none());
    }
}
