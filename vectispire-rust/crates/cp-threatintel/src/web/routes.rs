//! Threat intelligence's read routes — `ThreatIntelController.getStatus` and `EpssController`'s two reads:
//!
//! - `GET /api/v1/threat-intel/status` — a governance reader's: the feeds are the deployment's, no target's.
//! - `GET /api/v1/epss/priorities` — any account's, **narrowed to what its allowance sees**.
//! - `GET /api/v1/epss/cve/{cveId}` — any account's: what the two public feeds say about one CVE, which names no
//!   target; a CVE neither recorded is a bare 404, as `ResponseEntity.notFound()` answers.
//!
//! - `POST /api/v1/threat-intel/sync` and `POST /api/v1/epss/sync` — a security lead's: outbound, repeatable at will
//!   and rate-limited by whoever serves it; not destructive, which is why it is a lead's rather than an
//!   administrator's, but not a reader's. **The same synchronisation** from either screen — the CISA KEV catalogue and
//!   FIRST's EPSS file, one audit entry each — named by the screen it came from, the actor's fallback `system`.
//!
//! None of them takes an API key: neither controller is marked `@AcceptsApiKey`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::HeaderMap;
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_access::CallerScope;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem, Scoped};

use super::json::{RecordJson, SyncStatusJson};
use crate::feeds::{FeedError, ThreatIntel};
use crate::prioritization::EpssPrioritizationService;
use crate::sync::{Origin, ThreatIntelFeedService};

/// The services a route reaches.
#[derive(Debug, Clone)]
pub struct Services {
    pub feeds: ThreatIntel,
    pub ranking: EpssPrioritizationService,
    pub sync: Arc<ThreatIntelFeedService>,
}

/// `RequestActors.of(principal, request, "system")`.
fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: Some(vectispire_cp_access::security::actor_name(&caller.0, "system")),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

/// The two sync routes: one synchronisation, named by the screen it was asked from.
fn sync_route(path: &'static str, origin: Origin, services: Arc<Services>) -> RouteEntry {
    Route::post(path).requires(Access::SecurityLead).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap| {
            let s = services.clone();
            async move {
                match s.sync.sync_threat_intel(&actor(&caller, &address, &headers), origin).await {
                    Ok(status) => ok(&SyncStatusJson::from(status)),
                    Err(error) => failed(&error),
                }
            }
        },
    )
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
    let (status, priorities, lookup) = (services.clone(), services.clone(), services.clone());
    vec![
        sync_route("/api/v1/threat-intel/sync", Origin::ThreatIntelligenceScreen, services.clone()),
        sync_route("/api/v1/epss/sync", Origin::EpssScreen, services),
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
