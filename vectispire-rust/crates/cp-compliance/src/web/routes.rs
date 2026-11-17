//! Compliance's routes — so far `ComplianceController`'s summary and framework, and `ScopeComplianceController`:
//!
//! - `GET /api/v1/compliance/summary`, `GET /api/v1/compliance/frameworks/{framework}`
//! - `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance`
//!
//! Every one resolves the caller's allowance and reads only what it permits; a scope the caller sees nothing of is
//! refused as an absent one, **404 and never 403**.

use std::sync::Arc;

use crate::decisions::ComplianceFramework;
use axum::body::Body;
use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{ApiKeyScope, Problem, Scoped};

use super::read;
use crate::error::ComplianceError;
use crate::matrix::ComplianceService;
use crate::scope::ScopeComplianceService;

#[allow(clippy::result_large_err)]
fn allowance(scope: CallerScope) -> Result<Allowance, Response> {
    scope.map_err(|_| {
        Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "Could not resolve caller visibility").into_response()
    })
}

fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn answer<T: Serialize>(result: Result<T, ComplianceError>) -> Response {
    match result {
        Ok(value) => ok(&value),
        Err(refused) => refused.into_response(),
    }
}

macro_rules! or_answer {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(response) => return response,
        }
    };
}

/// The services a route reaches, shared.
#[derive(Debug)]
pub struct Services {
    pub compliance: ComplianceService,
    pub scopes: ScopeComplianceService,
}

/// A read over the caller's allowance and the query string, an API key of the read scope accepted.
fn read_route<F, Fut>(path: &str, services: &Arc<Services>, handler: F) -> RouteEntry
where
    F: Fn(Arc<Services>, Allowance, Option<String>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let services = services.clone();
    Route::get(path).requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
        move |Scoped(scope): Scoped<CallerScope>, RawQuery(query): RawQuery| {
            let (services, handler) = (services.clone(), handler.clone());
            async move {
                let allowed = or_answer!(allowance(scope));
                handler(services, allowed, query).await
            }
        },
    )
}

/// The same, with one path variable handed as it was written.
fn read_route_of<F, Fut>(path: &str, services: &Arc<Services>, handler: F) -> RouteEntry
where
    F: Fn(Arc<Services>, Allowance, String) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let services = services.clone();
    Route::get(path).requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
        move |Scoped(scope): Scoped<CallerScope>, Path(raw): Path<String>| {
            let (services, handler) = (services.clone(), handler.clone());
            async move {
                let allowed = or_answer!(allowance(scope));
                handler(services, allowed, raw).await
            }
        },
    )
}

/// Every route of the module so far.
pub fn routes(services: Arc<Services>) -> Vec<RouteEntry> {
    let s = &services;
    vec![
        read_route("/api/v1/compliance/summary", s, async |m, allowed, query| {
            let target = read::query_string(query.as_deref(), "targetId");
            answer(m.compliance.summary_of(target.as_deref(), &allowed.visibility).await)
        }),
        // Lenient, as `ComplianceFramework.fromIdentifier`: `iso-27001`, `NIS2` and `pci_dss` all name one.
        read_route_of("/api/v1/compliance/frameworks/{framework}", s, async |m, allowed, raw| {
            let framework = or_answer!(
                ComplianceFramework::from_identifier(&raw)
                    .map_err(|unknown| ComplianceError::Invalid(unknown.to_string()).into_response())
            );
            answer(m.compliance.evaluation(framework, &allowed.visibility).await)
        }),
        read_route_of("/api/v1/projects/{id}/compliance", s, async |m, allowed, raw| {
            let id = or_answer!(read::path_long("id", &raw).map_err(IntoResponse::into_response));
            answer(m.scopes.of_project(id, &allowed).await)
        }),
        read_route_of("/api/v1/solutions/{id}/compliance", s, async |m, allowed, raw| {
            let id = or_answer!(read::path_long("id", &raw).map_err(IntoResponse::into_response));
            answer(m.scopes.of_solution(id, &allowed).await)
        }),
    ]
}
