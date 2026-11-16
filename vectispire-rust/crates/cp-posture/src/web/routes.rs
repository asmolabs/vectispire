//! The posture module's routes — `DashboardController`, `QualityController`, `SecurityDebtController`,
//! `AttackPathController` and `ScorecardController`:
//!
//! - `GET /api/v1/dashboard` (`overview_2`), `/dashboard/trends`, `/dashboard/posture-analytics`
//! - `GET /api/v1/quality/overview` (`overview_1`)
//! - `GET /api/v1/remediation/distribution`, `/debt`, `/coverage` (`coverage_1`), `/high-impact-fixes`
//! - `GET /api/v1/attack-paths/repositories/{repoId}`, `/attack-paths/overview`
//! - `GET /api/v1/scorecards/repositories/{repoId}`, `/containers/{containerId}`, `/global`, `/simulation`
//! - `GET /api/v1/scorecards/badges/{token}.svg` — anonymous, named by a token
//! - `GET`, `POST`, `DELETE /api/v1/scorecards/repositories/{repoId}/badge`
//!
//! Every route but the badge's resolves the caller's allowance; one naming a target refuses a hidden one with **404**,
//! never 403, through the services (`rows::require_visible`) — before the row is read and before any parameter of
//! the figure, so the refusal says nothing a stranger could not know.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem, Scoped};

use super::read;
use crate::PostureModule;
use crate::badges::Badge;
use crate::distribution::{DEFAULT_WINDOW_DAYS, RemediationDistributionView};
use crate::error::PostureError;
use crate::simulation::Requested;

/// Not a repository's id but the guard's own sentence: a second wording here would tell an absent repository from a
/// hidden one.
const TARGET_NOT_FOUND: &str = "Target not found.";
const REPOSITORY_NOT_FOUND: &str = "Repository not found.";
const NO_BADGE: &str = "No badge under this token.";

const BADGE: &str = "/api/v1/scorecards/repositories/{repoId}/badge";

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

fn answer<T: Serialize>(result: Result<T, PostureError>) -> Response {
    match result {
        Ok(value) => ok(&value),
        Err(refused) => refused.into_response(),
    }
}

/// A figure that may be absent: absent is a 404 carrying `absent`.
fn found<T: Serialize>(result: Result<Option<T>, PostureError>, absent: &str) -> Response {
    match result {
        Ok(Some(value)) => ok(&value),
        Ok(None) => Problem::handler(StatusCode::NOT_FOUND, absent).into_response(),
        Err(refused) => refused.into_response(),
    }
}

fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

/// `BadgeState`: what to paste into a README, absent when no badge is published.
#[derive(Debug, Serialize)]
struct BadgeState {
    published: bool,
    token: Option<String>,
    url: Option<String>,
}

fn badge_state(result: Result<Option<Badge>, PostureError>) -> Response {
    let state = result.map(|badge| {
        badge.map(|badge| match badge.token {
            Some(token) => BadgeState {
                published: true,
                url: Some(format!("/api/v1/scorecards/badges/{token}.svg")),
                token: Some(token),
            },
            None => BadgeState { published: false, token: None, url: None },
        })
    });
    found(state, REPOSITORY_NOT_FOUND)
}

/// `days`, an `int` with a default.
#[allow(clippy::result_large_err)]
fn days(query: Option<&str>, default: i32) -> Result<i32, Response> {
    read::query_int(query, "days").map(|days| days.unwrap_or(default)).map_err(IntoResponse::into_response)
}

/// `repoId` and `containerId`, both optional `Long`s.
#[allow(clippy::result_large_err)]
fn targets(query: Option<&str>) -> Result<(Option<i64>, Option<i64>), Response> {
    let repository = read::query_long(query, "repoId").map_err(IntoResponse::into_response)?;
    let container = read::query_long(query, "containerId").map_err(IntoResponse::into_response)?;
    Ok((repository, container))
}

macro_rules! or_answer {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(response) => return response,
        }
    };
}

/// A read-only route over the caller's allowance and the query string.
fn scoped_get<F, Fut>(path: &str, access: Access, module: &Arc<Services>, handler: F) -> RouteEntry
where
    F: Fn(Arc<Services>, Allowance, Option<String>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let module = module.clone();
    Route::get(path).requires(access).scoped().handler(
        move |Scoped(scope): Scoped<CallerScope>, RawQuery(query): RawQuery| {
            let (module, handler) = (module.clone(), handler.clone());
            async move {
                let allowed = or_answer!(allowance(scope));
                handler(module, allowed, query).await
            }
        },
    )
}

/// A read-only route naming one target by a numeric path variable.
fn scoped_get_by_id<F, Fut>(path: &str, name: &'static str, module: &Arc<Services>, handler: F) -> RouteEntry
where
    F: Fn(Arc<Services>, Allowance, i64, Option<String>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let module = module.clone();
    Route::get(path).requires(Access::Account).scoped().handler(
        move |Scoped(scope): Scoped<CallerScope>, Path(raw): Path<String>, RawQuery(query): RawQuery| {
            let (module, handler) = (module.clone(), handler.clone());
            async move {
                let allowed = or_answer!(allowance(scope));
                let id = or_answer!(read::path_long(name, &raw).map_err(IntoResponse::into_response));
                handler(module, allowed, id, query).await
            }
        },
    )
}

/// The services a route reaches, shared.
pub struct Services {
    pub scorecards: Arc<crate::scorecards::SecurityScorecards>,
    pub badges: Arc<crate::badges::ScorecardBadges>,
    pub simulations: Arc<crate::simulation::ScoreSimulations>,
    pub dashboard: Arc<crate::dashboard::Dashboard>,
    pub quality: Arc<crate::quality::Quality>,
    pub debt: Arc<crate::debt::SecurityDebt>,
    pub distributions: Arc<crate::distribution::RemediationDistributions>,
    pub attack_paths: Arc<crate::attack_paths::AttackPaths>,
}

/// Every route of the module.
pub fn routes(module: &PostureModule) -> Vec<RouteEntry> {
    let services = Arc::new(Services {
        scorecards: module.scorecards.clone(),
        badges: module.badges.clone(),
        simulations: module.simulations.clone(),
        dashboard: module.dashboard.clone(),
        quality: module.quality.clone(),
        debt: module.debt.clone(),
        distributions: module.distributions.clone(),
        attack_paths: module.attack_paths.clone(),
    });
    let s = &services;
    let mut entries = vec![
        // ── the dashboard ──
        scoped_get("/api/v1/dashboard", Access::Account, s, async |m, allowed, _| {
            answer(m.dashboard.overview(&allowed.visibility).await)
        }),
        scoped_get("/api/v1/dashboard/trends", Access::Account, s, async |m, allowed, query| {
            let days = or_answer!(days(query.as_deref(), 90));
            answer(m.dashboard.trends(days, &allowed.visibility).await)
        }),
        scoped_get("/api/v1/dashboard/posture-analytics", Access::Account, s, async |m, allowed, query| {
            let days = or_answer!(days(query.as_deref(), 30));
            answer(m.dashboard.posture_analytics(days, &allowed.visibility).await)
        }),
        // ── quality ──
        scoped_get("/api/v1/quality/overview", Access::Account, s, async |m, allowed, _| {
            answer(m.quality.overview(&allowed.visibility).await)
        }),
        // ── remediation ──
        scoped_get("/api/v1/remediation/distribution", Access::Account, s, async |m, allowed, query| {
            let days = or_answer!(days(query.as_deref(), DEFAULT_WINDOW_DAYS));
            answer(
                m.distributions
                    .distribution(days, &allowed.visibility)
                    .await
                    .map(|d| RemediationDistributionView::of(&d)),
            )
        }),
        scoped_get("/api/v1/remediation/debt", Access::Account, s, async |m, allowed, query| {
            let (repository, container) = or_answer!(targets(query.as_deref()));
            answer(m.debt.calculate_debt(repository, container, &allowed.visibility).await)
        }),
        scoped_get("/api/v1/remediation/coverage", Access::Account, s, async |m, allowed, query| {
            let (repository, container) = or_answer!(targets(query.as_deref()));
            answer(m.debt.coverage(repository, container, &allowed.visibility).await)
        }),
        scoped_get("/api/v1/remediation/high-impact-fixes", Access::Account, s, async |m, allowed, query| {
            let (repository, container) = or_answer!(targets(query.as_deref()));
            let limit = or_answer!(
                read::query_int(query.as_deref(), "limit")
                    .map(|limit| limit.unwrap_or(10))
                    .map_err(IntoResponse::into_response)
            );
            answer(m.debt.high_impact_fixes(repository, container, limit, &allowed.visibility).await)
        }),
        // ── attack paths ──
        scoped_get_by_id("/api/v1/attack-paths/repositories/{repoId}", "repoId", s, async |m, allowed, id, _| {
            match m.attack_paths.graph(id, &allowed.visibility).await {
                Ok(Some(graph)) => ok(&graph),
                // `ResponseEntity.notFound().build()`: a repository the caller could see and that is gone — no body.
                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                Err(refused) => refused.into_response(),
            }
        }),
        scoped_get("/api/v1/attack-paths/overview", Access::Account, s, async |m, allowed, query| {
            let limit = or_answer!(read::query_long(query.as_deref(), "limit").map_err(IntoResponse::into_response));
            let offset = or_answer!(read::query_long(query.as_deref(), "offset").map_err(IntoResponse::into_response));
            answer(m.attack_paths.overview(&allowed.visibility, limit, offset).await)
        }),
        // ── scorecards ──
        scoped_get_by_id("/api/v1/scorecards/repositories/{repoId}", "repoId", s, async |m, allowed, id, _| {
            found(m.scorecards.repository_scorecard(id, &allowed.visibility).await, TARGET_NOT_FOUND)
        }),
        scoped_get_by_id("/api/v1/scorecards/containers/{containerId}", "containerId", s, async |m, allowed, id, _| {
            found(m.scorecards.container_scorecard(id, &allowed.visibility).await, TARGET_NOT_FOUND)
        }),
        scoped_get("/api/v1/scorecards/global", Access::Account, s, async |m, allowed, _| {
            answer(m.scorecards.portfolio_scorecard(&allowed.visibility).await)
        }),
        // Administrators only — a deliberation about the product, not a figure anyone acts on — and narrowed to the
        // caller's allowance all the same, so the day the marker admits a narrower role the route does not leak.
        scoped_get("/api/v1/scorecards/simulation", Access::Administrator, s, async |m, allowed, query| {
            #[allow(clippy::result_large_err)]
            let weight = |name| read::query_double(query.as_deref(), name).map_err(IntoResponse::into_response);
            let requested = Requested {
                exploited: or_answer!(weight("exploited")),
                critical: or_answer!(weight("critical")),
                high: or_answer!(weight("high")),
                medium: or_answer!(weight("medium")),
                low: or_answer!(weight("low")),
                licence: or_answer!(weight("licence")),
                k: or_answer!(weight("k")),
            };
            answer(m.simulations.simulate(&allowed, requested).await)
        }),
        scoped_get_by_id(BADGE, "repoId", s, async |m, allowed, id, _| {
            badge_state(m.badges.state(id, &allowed.visibility).await)
        }),
    ];

    // ── the published badge: anonymous by necessity, and named by a token for exactly that reason ──
    let badges = services.badges.clone();
    entries.push(
        Route::get("/api/v1/scorecards/badges/{token}.svg").requires(Access::Anonymous).names_no_target().handler(
            move |Path(file): Path<String>| {
                let badges = badges.clone();
                async move {
                    let Some(token) = vectispire_cp_http::routes::suffixed(&file, ".svg") else {
                        return Problem::handler(StatusCode::NOT_FOUND, NO_BADGE).into_response();
                    };
                    match badges.published_svg(token).await {
                        Ok(Some(svg)) => {
                            let mut response = Response::new(Body::from(svg));
                            let headers = response.headers_mut();
                            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=300, public"));
                            // Embedded in a README on another origin, which the chain's same-origin policy would block.
                            headers.insert("Cross-Origin-Resource-Policy", HeaderValue::from_static("cross-origin"));
                            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml"));
                            response
                        }
                        // An unknown token and a revoked one are the same absence.
                        Ok(None) => Problem::handler(StatusCode::NOT_FOUND, NO_BADGE).into_response(),
                        Err(failed) => failed.into_response(),
                    }
                }
            },
        ),
    );

    // ── publishing and revoking: a decision somebody makes ──
    for publish in [true, false] {
        let badges = services.badges.clone();
        let route = if publish { Route::post(BADGE) } else { Route::delete(BADGE) };
        entries.push(route.requires(Access::WriteAccount).scoped().handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Scoped(scope): Scoped<CallerScope>,
                  Path(raw): Path<String>| {
                let badges = badges.clone();
                async move {
                    let allowed = or_answer!(allowance(scope));
                    let id = or_answer!(read::path_long("repoId", &raw).map_err(IntoResponse::into_response));
                    let actor = actor(&caller, &address, &headers);
                    let result = if publish {
                        badges.publish(id, &allowed.visibility, &actor).await
                    } else {
                        badges.revoke(id, &allowed.visibility, &actor).await
                    };
                    badge_state(result)
                }
            },
        ));
    }
    entries
}
