//! Threat intelligence's read routes — `ThreatIntelController.getStatus` and `EpssController`'s two reads:
//!
//! - `GET /api/v1/threat-intel/status` — a governance reader's: the feeds are the deployment's, no target's.
//! - `GET /api/v1/epss/priorities` — any account's, **narrowed to what its allowance sees**.
//! - `GET /api/v1/epss/cve/{cveId}` — any account's: what the two public feeds say about one CVE, which names no
//!   target; a CVE neither recorded is a bare 404, as `ResponseEntity.notFound()` answers.
//!
//! None of them takes an API key: neither controller is marked `@AcceptsApiKey`. The two syncs wait for the outbound
//! fetches (stage 2).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_access::CallerScope;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Problem, Scoped};

use super::json::{RecordJson, SyncStatusJson};
use crate::feeds::{FeedError, ThreatIntel};
use crate::prioritization::EpssPrioritizationService;

/// The services a route reaches.
#[derive(Debug, Clone)]
pub struct Services {
    pub feeds: ThreatIntel,
    pub ranking: EpssPrioritizationService,
}

fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A store that did not answer: logged, and a 500 that says nothing more.
fn failed(error: &FeedError) -> Response {
    tracing::error!("A threat intelligence answer could not be read: {error}");
    Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An unexpected error occurred.").into_response()
}

/// Every read route of the module.
pub fn routes(services: Arc<Services>) -> Vec<RouteEntry> {
    let (status, priorities, lookup) = (services.clone(), services.clone(), services);
    vec![
        Route::get("/api/v1/threat-intel/status").requires(Access::GovernanceRead).names_no_target().handler(
            move || {
                let s = status.clone();
                async move {
                    match s.feeds.status().await {
                        Ok(status) => ok(&SyncStatusJson::from(status)),
                        Err(error) => failed(&error),
                    }
                }
            },
        ),
        Route::get("/api/v1/epss/priorities").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>| {
                let s = priorities.clone();
                async move {
                    let Ok(allowed) = scope else {
                        return Problem::handler(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Could not resolve caller visibility",
                        )
                        .into_response();
                    };
                    match s.ranking.fleet_summary(&allowed.visibility).await {
                        Ok(summary) => ok(&summary),
                        Err(error) => failed(&error),
                    }
                }
            },
        ),
        Route::get("/api/v1/epss/cve/{cveId}").requires(Access::Account).names_no_target().handler(
            move |Path(cve_id): Path<String>| {
                let s = lookup.clone();
                async move {
                    match s.feeds.lookup_cve(Some(&cve_id)).await {
                        Ok(Some(record)) => ok(&RecordJson::from(record)),
                        Ok(None) => StatusCode::NOT_FOUND.into_response(),
                        Err(error) => failed(&error),
                    }
                }
            },
        ),
    ]
}
