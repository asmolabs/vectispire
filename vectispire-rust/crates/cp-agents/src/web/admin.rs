//! Administration routes for remote agents — `AgentsAdminController`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Path, RawQuery, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, JsonBody, Problem};

use crate::error::AgentError;
use crate::internal::admin_service::{AgentAdministrationService, Change, Declaration, Unroutable};

pub fn routes(admin: Arc<AgentAdministrationService>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    // 1. GET /api/v1/admin/agents
    let a = admin.clone();
    entries.push(Route::get("/api/v1/admin/agents").requires(Access::Administrator).names_no_target().handler(
        move |RawQuery(query): RawQuery| {
            let a = a.clone();
            async move {
                let (limit, offset) = parse_limit_offset(query.as_deref());
                match a.list(limit, offset).await {
                    Ok(list) => ok(&list),
                    Err(err) => err_response(err),
                }
            }
        },
    ));

    // 2. POST /api/v1/admin/agents
    let a = admin.clone();
    entries.push(Route::post("/api/v1/admin/agents").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let a = a.clone();
            async move {
                let actor = actor(&caller, &address, &headers);
                let body = match read_json::<AgentCreateRequest>(request).await {
                    Ok(b) => b,
                    Err(p) => return p.into_response(),
                };
                let decl = Declaration {
                    name: body.name.unwrap_or_default(),
                    description: body.description,
                    credentials_mode: body.credentials_mode,
                    labels: body.labels,
                    max_concurrent: body.max_concurrent,
                };
                match a.declare(decl, &actor).await {
                    Ok(declared) => ok(&declared),
                    Err(err) => err_response(err),
                }
            }
        },
    ));

    // 3. GET /api/v1/admin/agents/activity
    let a = admin.clone();
    entries.push(
        Route::get("/api/v1/admin/agents/activity").requires(Access::Administrator).names_no_target().handler(
            move || {
                let a = a.clone();
                async move {
                    match a.activity().await {
                        Ok(activity) => {
                            let summary = AgentActivitySummary::of(activity);
                            ok(&summary)
                        }
                        Err(err) => err_response(err),
                    }
                }
            },
        ),
    );

    // 4. GET /api/v1/admin/agents/non-routables
    let a = admin.clone();
    entries.push(
        Route::get("/api/v1/admin/agents/non-routables").requires(Access::Administrator).names_no_target().handler(
            move || {
                let a = a.clone();
                async move {
                    match a.unroutable().await {
                        Ok(unroutable) => {
                            let views: Vec<UnroutableLabel> =
                                unroutable.into_iter().map(UnroutableLabel::from).collect();
                            ok(&views)
                        }
                        Err(err) => err_response(err),
                    }
                }
            },
        ),
    );

    // 5. GET /api/v1/admin/agents/credentialed-backlog
    let a = admin.clone();
    entries.push(
        Route::get("/api/v1/admin/agents/credentialed-backlog")
            .requires(Access::Administrator)
            .names_no_target()
            .handler(move || {
                let a = a.clone();
                async move {
                    match a.unserved_backlog().await {
                        Ok(unserved) => ok(&UnservedCredentialedScans {
                            scans: unserved.scans,
                            labels: unserved.labels,
                            kept_agents: unserved.kept_agents,
                        }),
                        Err(err) => err_response(err),
                    }
                }
            }),
    );

    // 6. PATCH /api/v1/admin/agents/{id}
    let a = admin.clone();
    entries.push(Route::patch("/api/v1/admin/agents/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Path(id_str): Path<String>,
              request: Request| {
            let a = a.clone();
            async move {
                let id = match parse_uuid(&id_str) {
                    Ok(id) => id,
                    Err(p) => return p.into_response(),
                };
                let actor = actor(&caller, &address, &headers);
                let body = match read_json::<AgentUpdateRequest>(request).await {
                    Ok(b) => b,
                    Err(p) => return p.into_response(),
                };
                let change = Change { enabled: body.enabled, labels: body.labels, max_concurrent: body.max_concurrent };
                match a.change(id, change, &actor).await {
                    Ok(changed) => {
                        let mut answer = HashMap::new();
                        answer.insert("id", serde_json::to_value(changed.id).unwrap_or_default());
                        answer.insert("enabled", serde_json::to_value(changed.enabled).unwrap_or_default());
                        answer.insert("labels", serde_json::to_value(changed.labels).unwrap_or_default());
                        ok(&answer)
                    }
                    Err(err) => err_response(err),
                }
            }
        },
    ));

    // 7. PUT /api/v1/admin/agents/{id}/signing-key
    let a = admin.clone();
    entries.push(
        Route::put("/api/v1/admin/agents/{id}/signing-key").requires(Access::Administrator).names_no_target().handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Path(id_str): Path<String>,
                  request: Request| {
                let a = a.clone();
                async move {
                    let id = match parse_uuid(&id_str) {
                        Ok(id) => id,
                        Err(p) => return p.into_response(),
                    };
                    let actor = actor(&caller, &address, &headers);
                    let body = match read_json::<SigningKeyRequest>(request).await {
                        Ok(b) => b,
                        Err(p) => return p.into_response(),
                    };
                    match a.pin_signing_key(id, body.public_key.as_deref(), &actor).await {
                        Ok(pinned) => ok(&PinnedSigningKey {
                            id: pinned.id,
                            signs_results: pinned.signs_results,
                            private_key: pinned.private_key,
                        }),
                        Err(err) => err_response(err),
                    }
                }
            },
        ),
    );

    // 8. DELETE /api/v1/admin/agents/{id}/sealing-key
    let a = admin.clone();
    entries.push(
        Route::delete("/api/v1/admin/agents/{id}/sealing-key")
            .requires(Access::Administrator)
            .names_no_target()
            .handler(move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id_str): Path<String>| {
                let a = a.clone();
                async move {
                    let id = match parse_uuid(&id_str) {
                        Ok(id) => id,
                        Err(p) => return p.into_response(),
                    };
                    let actor = actor(&caller, &address, &headers);
                    match a.reset_sealing_key(id, &actor).await {
                        Ok(()) => no_content(),
                        Err(err) => err_response(err),
                    }
                }
            }),
    );

    // 9. DELETE /api/v1/admin/agents/{id}
    let a = admin;
    entries.push(Route::delete("/api/v1/admin/agents/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id_str): Path<String>| {
            let a = a.clone();
            async move {
                let id = match parse_uuid(&id_str) {
                    Ok(id) => id,
                    Err(p) => return p.into_response(),
                };
                let actor = actor(&caller, &address, &headers);
                match a.remove(id, &actor).await {
                    Ok(()) => no_content(),
                    Err(err) => err_response(err),
                }
            }
        },
    ));

    entries
}

fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(str::to_owned),
    }
}

fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn no_content() -> Response {
    Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty()).unwrap_or_default()
}

fn err_response(err: AgentError) -> Response {
    let problem: Problem = err.into();
    problem.into_response()
}

fn parse_uuid(text: &str) -> Result<Uuid, Problem> {
    Uuid::parse_str(text).map_err(|_| Problem::handler(StatusCode::BAD_REQUEST, format!("Invalid UUID: \"{text}\".")))
}

fn parse_limit_offset(raw: Option<&str>) -> (Option<i64>, Option<i64>) {
    let mut limit = None;
    let mut offset = None;
    if let Some(query) = raw {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "limit" {
                    limit = v.parse::<i64>().ok();
                } else if k == "offset" {
                    offset = v.parse::<i64>().ok();
                }
            }
        }
    }
    (limit, offset)
}

async fn read_json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, Problem> {
    JsonBody::<T>::from_request(request, &()).await.map(|JsonBody(body)| body)
}

#[derive(Deserialize)]
struct AgentCreateRequest {
    name: Option<String>,
    description: Option<String>,
    #[serde(rename = "credentials_mode")]
    credentials_mode: Option<String>,
    labels: Option<String>,
    #[serde(rename = "max_concurrent")]
    max_concurrent: Option<i32>,
}

#[derive(Deserialize)]
struct AgentUpdateRequest {
    enabled: Option<bool>,
    labels: Option<String>,
    #[serde(rename = "max_concurrent")]
    max_concurrent: Option<i32>,
}

#[derive(Deserialize)]
struct SigningKeyRequest {
    #[serde(rename = "public_key")]
    public_key: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PinnedSigningKey {
    id: Uuid,
    signs_results: bool,
    private_key: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnroutableLabel {
    label: String,
    queued: i64,
}

impl From<Unroutable> for UnroutableLabel {
    fn from(u: Unroutable) -> Self {
        Self { label: u.label, queued: u.queued }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnservedCredentialedScans {
    scans: i64,
    labels: Vec<String>,
    kept_agents: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunningScanItem {
    scan_id: i64,
    target_type: String,
    target_id: i64,
    target_name: String,
    branch: Option<String>,
    agent_id: Option<String>,
    agent_name: Option<String>,
    claimed_at: String,
    duration_seconds: i64,
    required_label: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingScanItem {
    scan_id: i64,
    target_type: String,
    target_id: i64,
    target_name: String,
    branch: Option<String>,
    required_label: Option<String>,
    queued_at: String,
    wait_duration_seconds: i64,
    is_routable: bool,
    position_in_queue: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueueStats {
    total_agents: i32,
    online_agents: i32,
    busy_agents: i32,
    idle_agents: i32,
    running_scans_count: i64,
    pending_scans_count: i64,
    scans_completed24h: i64,
    avg_scan_duration_seconds: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentActivitySummary {
    running_scans: Vec<RunningScanItem>,
    pending_scans: Vec<PendingScanItem>,
    stats: QueueStats,
}

impl AgentActivitySummary {
    fn of(act: crate::internal::admin_service::Activity) -> Self {
        let running_scans = act
            .running
            .into_iter()
            .map(|r| RunningScanItem {
                scan_id: r.scan_id,
                target_type: r.target_type,
                target_id: r.target_id,
                target_name: r.target_name,
                branch: r.branch,
                agent_id: r.agent_id,
                agent_name: r.agent_name,
                claimed_at: vectispire_cp_audit::iso_instant(r.claimed_at),
                duration_seconds: r.duration_seconds,
                required_label: r.required_label,
            })
            .collect();

        let pending_scans = act
            .pending
            .into_iter()
            .map(|p| PendingScanItem {
                scan_id: p.scan_id,
                target_type: p.target_type,
                target_id: p.target_id,
                target_name: p.target_name,
                branch: p.branch,
                required_label: p.required_label,
                queued_at: vectispire_cp_audit::iso_instant(p.queued_at),
                wait_duration_seconds: p.wait_duration_seconds,
                is_routable: p.routable,
                position_in_queue: p.position_in_queue,
            })
            .collect();

        let f = act.figures;
        let stats = QueueStats {
            total_agents: f.total_agents,
            online_agents: f.online_agents,
            busy_agents: f.busy_agents,
            idle_agents: f.idle_agents,
            running_scans_count: f.running_scans_count,
            pending_scans_count: f.pending_scans_count,
            scans_completed24h: f.scans_completed_24h,
            avg_scan_duration_seconds: f.avg_scan_duration_seconds,
        };

        Self { running_scans, pending_scans, stats }
    }
}
