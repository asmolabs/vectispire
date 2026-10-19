//! HTTP controllers and routes of the inventory module (18 endpoints).

pub mod read;

use std::sync::Arc;

use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use serde::Serialize;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{ApiKeyScope, Caller, ClientAddress, JsonBody, Problem, Scoped};
use vectispire_cp_targets::Targets;

use crate::Inventory;
use crate::error::InventoryError;
use crate::license::LicensePolicy;

pub fn routes(inventory: Arc<Inventory>, targets: Arc<Targets>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    license_routes(&inventory, &targets, &mut entries);
    blast_radius_routes(&inventory, &mut entries);
    diff_routes(&inventory, &mut entries);
    inventory_query_routes(&inventory, &mut entries);
    project_inventory_routes(&inventory, &targets, &mut entries);
    api_surface_routes(&inventory, &mut entries);
    entries
}

struct Call {
    actor: RequestActor,
}

fn call(Caller(principal): &Caller, address: &ClientAddress, headers: &HeaderMap) -> Call {
    Call {
        actor: RequestActor {
            username: principal.actor(),
            ip_address: Some(address.0.clone()),
            user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
        },
    }
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_string(body) {
        Ok(json) => {
            (status, [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))], json).into_response()
        }
        Err(e) => {
            Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {e}")).into_response()
        }
    }
}

fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

#[allow(clippy::result_large_err)]
fn allowance(scope: CallerScope) -> Result<Allowance, Response> {
    scope.map_err(|_| {
        Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "Could not resolve caller visibility").into_response()
    })
}

macro_rules! read_param {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(problem) => return problem.into_response(),
        }
    };
}

macro_rules! attempt {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(err) => return $crate::error::InventoryError::from(err).into_response(),
        }
    };
}

// ── 1. License routes (6) ─────────────────────────────────────────────────────────────

fn license_routes(inventory: &Arc<Inventory>, _targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    // GET /api/v1/licenses/conflicts
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/licenses/conflicts").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let repo_id = read_param!(read::query_long(query.as_deref(), "repo_id"));
                let container_id = read_param!(read::query_long(query.as_deref(), "container_id"));
                let proprietary = read_param!(read::query_bool(query.as_deref(), "proprietary", true));
                let limit = read_param!(read::query_long(query.as_deref(), "limit"));
                let offset = read_param!(read::query_long(query.as_deref(), "offset"));

                let conflicts = attempt!(
                    inv.licenses()
                        .evaluate_conflicts(&allow.visibility, repo_id, container_id, proprietary, limit, offset)
                        .await
                );
                json_response(StatusCode::OK, &conflicts)
            }
        },
    ));

    // GET /api/v1/licenses/inventory
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/licenses/inventory").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let repo_id = read_param!(read::query_long(query.as_deref(), "repo_id"));
                let container_id = read_param!(read::query_long(query.as_deref(), "container_id"));
                let limit = read_param!(read::query_long(query.as_deref(), "limit"));
                let offset = read_param!(read::query_long(query.as_deref(), "offset"));

                let entries = attempt!(
                    inv.licenses().get_inventory(&allow.visibility, repo_id, container_id, limit, offset).await
                );
                json_response(StatusCode::OK, &entries)
            }
        },
    ));

    // GET /api/v1/licenses/matrix
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/licenses/matrix").requires(Access::Account).scoped().handler(move || {
        let inv = inv.clone();
        async move {
            let rules = inv.licenses().get_compatibility_rules();
            json_response(StatusCode::OK, &rules)
        }
    }));

    // GET /api/v1/licenses/policy
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/licenses/policy").requires(Access::Account).scoped().handler(move || {
        let inv = inv.clone();
        async move {
            let policy = match inv.licenses().get_policy().await {
                Ok(p) => p,
                Err(e) => return InventoryError::Store(e).into_response(),
            };
            json_response(StatusCode::OK, &policy)
        }
    }));

    // PUT /api/v1/licenses/policy
    let inv = inventory.clone();
    entries.push(Route::put("/api/v1/licenses/policy").requires(Access::SecurityLead).scoped().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, JsonBody(policy): JsonBody<LicensePolicy>| {
            let inv = inv.clone();
            async move {
                let c = call(&caller, &address, &headers);
                let updated = attempt!(inv.licenses().update_policy(policy, &c.actor).await);
                json_response(StatusCode::OK, &updated)
            }
        },
    ));

    // GET /api/v1/licenses/summary
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/licenses/summary").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let repo_id = read_param!(read::query_long(query.as_deref(), "repo_id"));
                let container_id = read_param!(read::query_long(query.as_deref(), "container_id"));

                let summary = attempt!(inv.licenses().get_summary(&allow.visibility, repo_id, container_id).await);
                json_response(StatusCode::OK, &summary)
            }
        },
    ));
}

// ── 2. Blast Radius routes (2) ────────────────────────────────────────────────────────

fn blast_radius_routes(inventory: &Arc<Inventory>, entries: &mut Vec<RouteEntry>) {
    // GET /api/v1/blast-radius/explore
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/blast-radius/explore").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let q = read::query_string(query.as_deref(), "q");
                let report = attempt!(inv.blast_radius().explore(q.as_deref(), &allow.visibility).await);
                json_response(StatusCode::OK, &report)
            }
        },
    ));

    // GET /api/v1/blast-radius/top-impact
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/blast-radius/top-impact").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let limit = read_param!(read::query_int(query.as_deref(), "limit")).unwrap_or(10);
                let top = attempt!(inv.blast_radius().get_top_impact_packages(limit as usize, &allow.visibility).await);
                json_response(StatusCode::OK, &top)
            }
        },
    ));
}

// ── 3. SBOM Diff routes (2) ──────────────────────────────────────────────────────────

fn diff_routes(inventory: &Arc<Inventory>, entries: &mut Vec<RouteEntry>) {
    // GET /api/v1/sbom/diff
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/sbom/diff").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let from_scan = match read_param!(read::query_long(query.as_deref(), "fromScanId")) {
                    Some(id) => id,
                    None => return Problem::handler(StatusCode::BAD_REQUEST, "fromScanId is required").into_response(),
                };
                let to_scan = match read_param!(read::query_long(query.as_deref(), "toScanId")) {
                    Some(id) => id,
                    None => return Problem::handler(StatusCode::BAD_REQUEST, "toScanId is required").into_response(),
                };

                let report = attempt!(inv.diff().diff(from_scan, to_scan, &allow.visibility).await);
                match report {
                    Some(rep) => json_response(StatusCode::OK, &rep),
                    None => Problem::handler(StatusCode::NOT_FOUND, "Scan not found.").into_response(),
                }
            }
        },
    ));

    // GET /api/v1/sbom/diff/latest
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/sbom/diff/latest").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let repo_id = read_param!(read::query_long(query.as_deref(), "repoId"));
                let container_id = read_param!(read::query_long(query.as_deref(), "containerId"));

                let report = attempt!(inv.diff().diff_latest_target(repo_id, container_id, &allow.visibility).await);
                match report {
                    Some(rep) => json_response(StatusCode::OK, &rep),
                    None => Problem::handler(StatusCode::NOT_FOUND, "Scan not found.").into_response(),
                }
            }
        },
    ));
}

// ── 4. Inventory Query routes (2) ─────────────────────────────────────────────────────

fn inventory_query_routes(inventory: &Arc<Inventory>, entries: &mut Vec<RouteEntry>) {
    // GET /api/v1/inventory/search
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/inventory/search").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let name = match read::query_string(query.as_deref(), "name") {
                    Some(n) => n,
                    None => return Problem::handler(StatusCode::BAD_REQUEST, "name is required").into_response(),
                };
                let version = read::query_string(query.as_deref(), "version");

                let results = attempt!(inv.query().search(&name, version.as_deref(), &allow.visibility).await);
                json_response(StatusCode::OK, &results)
            }
        },
    ));

    // GET /api/v1/inventory/versions
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/inventory/versions").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let name = match read::query_string(query.as_deref(), "name") {
                    Some(n) => n,
                    None => return Problem::handler(StatusCode::BAD_REQUEST, "name is required").into_response(),
                };

                let versions = attempt!(inv.query().versions(&name, &allow.visibility).await);
                json_response(StatusCode::OK, &versions)
            }
        },
    ));
}

// ── 5. Project Inventory routes (1) ───────────────────────────────────────────────────

fn project_inventory_routes(inventory: &Arc<Inventory>, targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    // GET /api/v1/projects/{id}/components
    let inv = inventory.clone();
    let tgts = targets.clone();
    entries.push(
        Route::get("/api/v1/projects/{id}/components")
            .requires(Access::Account)
            .scoped()
            .accepts_api_key(ApiKeyScope::Read)
            .handler(
                move |_caller: Caller,
                      _address: ClientAddress,
                      _headers: HeaderMap,
                      _method: Method,
                      _uri: Uri,
                      Scoped(scope): Scoped<CallerScope>,
                      Path(id_str): Path<String>| {
                    let inv = inv.clone();
                    let tgts = tgts.clone();
                    async move {
                        let allow = match allowance(scope) {
                            Ok(a) => a,
                            Err(resp) => return resp,
                        };
                        let project_id = read_param!(read::path_long("id", &id_str));
                        let visible_scope = match tgts.visible_project(project_id, &allow).await {
                            Ok(s) => s,
                            Err(e) => return InventoryError::Target(e).into_response(),
                        };

                        let consolidated = attempt!(inv.consolidated().of(&visible_scope).await);
                        json_response(StatusCode::OK, &consolidated)
                    }
                },
            ),
    );
}

// ── 6. API Attack Surface routes (5) ──────────────────────────────────────────────────

fn api_surface_routes(inventory: &Arc<Inventory>, entries: &mut Vec<RouteEntry>) {
    // GET /api/v1/attack-surface
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/attack-surface").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let surface = attempt!(inv.apis().global_attack_surface(&allow.visibility).await);
                json_response(StatusCode::OK, &surface)
            }
        },
    ));

    // DELETE /api/v1/attack-surface
    let inv = inventory.clone();
    entries.push(Route::delete("/api/v1/attack-surface").requires(Access::SecurityLead).scoped().handler(move || {
        let inv = inv.clone();
        async move {
            attempt!(inv.apis().clear_all().await);
            no_content()
        }
    }));

    // GET /api/v1/repositories/{id}/apis
    let inv = inventory.clone();
    entries.push(Route::get("/api/v1/repositories/{id}/apis").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id_str): Path<String>| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let repo_id = read_param!(read::path_long("id", &id_str));
                let apis = attempt!(inv.apis().for_repository(repo_id, &allow.visibility).await);
                json_response(StatusCode::OK, &apis)
            }
        },
    ));

    // DELETE /api/v1/repositories/{id}/apis
    let inv = inventory.clone();
    entries.push(Route::delete("/api/v1/repositories/{id}/apis").requires(Access::SecurityLead).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id_str): Path<String>| {
            let inv = inv.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let repo_id = read_param!(read::path_long("id", &id_str));
                attempt!(inv.apis().clear_for_repository(repo_id, &allow.visibility).await);
                no_content()
            }
        },
    ));

    // GET /api/v1/repositories/{id}/apis/export/openapi
    let inv = inventory.clone();
    entries.push(
        Route::get("/api/v1/repositories/{id}/apis/export/openapi").requires(Access::Account).scoped().handler(
            move |_caller: Caller,
                  _address: ClientAddress,
                  _headers: HeaderMap,
                  _method: Method,
                  _uri: Uri,
                  Scoped(scope): Scoped<CallerScope>,
                  Path(id_str): Path<String>| {
                let inv = inv.clone();
                async move {
                    let allow = match allowance(scope) {
                        Ok(a) => a,
                        Err(resp) => return resp,
                    };
                    let repo_id = read_param!(read::path_long("id", &id_str));
                    let json_str =
                        attempt!(inv.apis().export_synthesized_open_api_json(repo_id, &allow.visibility).await);
                    let filename = format!("attachment; filename=\"openapi-repository-{repo_id}.json\"");
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, HeaderValue::from_static("application/json")),
                            (
                                header::CONTENT_DISPOSITION,
                                HeaderValue::try_from(filename)
                                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
                            ),
                        ],
                        json_str,
                    )
                        .into_response()
                }
            },
        ),
    );
}
