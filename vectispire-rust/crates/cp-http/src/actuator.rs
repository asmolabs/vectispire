//! `/actuator/**`, mounted behind the chain: the pages are `cp-runtime`'s, this is where they are served.
//!
//! **Not routes of the application.** Java's actuator endpoints are not handlers of its mapping, so none of the
//! per-route stages (password change, credential confinement, role) reach them: who may read what is the chain's
//! `access` layer alone — anonymous for `health`, an administrator's session for the rest, and the scrape token on
//! `/actuator/prometheus` ([`crate::access::Gate`]). These pages are therefore mounted beside the routes, not through
//! [`crate::routes::Route`], whose builder exists to make a route state its marker and visibility.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};

use crate::credentials::BoxFuture;
use crate::problem::Problem;

/// One page as the actuator answers it: a status, a content type (none for an empty answer), the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActuatorPage {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub body: String,
}

/// The actuator, as the stack asks it: the page at `path` (with its query string), `Ok(None)` for a path that is not
/// exposed — answered as any path with nothing under it — and `Err` for a page that could not be read.
pub trait ActuatorPages: Send + Sync {
    fn page<'a>(
        &'a self,
        path: &'a str,
        query: &'a str,
        base_url: &'a str,
    ) -> BoxFuture<'a, Result<Option<ActuatorPage>, String>>;
}

pub(crate) async fn serve(State(pages): State<Arc<dyn ActuatorPages>>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    // The links of `/actuator` name the address the caller used, as Spring writes them from the request.
    let host = request.headers().get(header::HOST).and_then(|value| value.to_str().ok()).unwrap_or("localhost");
    let base_url = format!("http://{host}");
    match pages.page(&path, &query, &base_url).await {
        Ok(Some(page)) => {
            let mut response = Response::new(Body::from(page.body));
            *response.status_mut() = StatusCode::from_u16(page.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            if let Some(content_type) = page.content_type {
                response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            }
            response
        }
        Ok(None) => crate::routes::not_found().await.into_response(),
        // A census that cannot be read is a failure, said as one and logged; never an empty census, which would tell
        // an operator in the middle of a rotation that nothing depends on the old key.
        Err(failure) => {
            tracing::error!("{path} could not be answered: {failure}");
            Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "This page could not be read.").at(path).into_response()
        }
    }
}
