//! Protocol routes spoken by remote agents — `AgentsController`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, RawQuery, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;

use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::principal::Credential;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};
use vectispire_domain::contract;
use vectispire_protocol::concurrency;
use vectispire_protocol::server::refusals;
use vectispire_protocol::server::{HelloRequest, RouteRefusal, SealingKeyRequest};

use crate::internal::poller::AgentJobPoller;
use crate::internal::protocol_service::{AgentProtocolService, AuthenticatedAgent};

const AGENT_SIGNATURE_HEADER: &str = "X-Vectispire-Agent-Signature";

pub fn routes(protocol: Arc<AgentProtocolService>, poller: Arc<AgentJobPoller>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    // 1. POST /api/v1/agent/hello
    let p = protocol.clone();
    entries.push(Route::post("/api/v1/agent/hello").requires(Access::AgentKey).names_no_target().handler(
        move |caller: Caller, request: Request| {
            let p = p.clone();
            async move {
                let agent = match authenticate(&caller, &p).await {
                    Ok(a) => a,
                    Err(p) => return p.into_response(),
                };
                let bytes = match read_bytes(request).await {
                    Ok(b) => b,
                    Err(p) => return p.into_response(),
                };
                let body = match HelloRequest::read(&bytes) {
                    Ok(Some(b)) => b,
                    _ => {
                        return Problem::handler(StatusCode::BAD_REQUEST, "A hello request needs a JSON body.")
                            .into_response();
                    }
                };
                match p.hello(&agent, &body).await {
                    Ok(answer) => {
                        let resp = HelloResponse {
                            id: agent.id,
                            name: agent.name,
                            contract_version: contract::VERSION.to_owned(),
                            max_concurrent: answer.max_concurrent,
                            credentials_mode: agent.credentials_mode,
                        };
                        ok(&resp)
                    }
                    Err(refusal) => refusal_response(refusal),
                }
            }
        },
    ));

    // 2. POST /api/v1/agent/sealing-key
    let p = protocol.clone();
    entries.push(Route::post("/api/v1/agent/sealing-key").requires(Access::AgentKey).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let p = p.clone();
            async move {
                let agent = match authenticate(&caller, &p).await {
                    Ok(a) => a,
                    Err(p) => return p.into_response(),
                };
                let actor = unnamed_actor(&address, &headers);
                let bytes = match read_bytes(request).await {
                    Ok(b) => b,
                    Err(p) => return p.into_response(),
                };
                let body = match SealingKeyRequest::read(&bytes) {
                    Ok(Some(b)) => b,
                    _ => return refusal_response(refusals::sealing_key_unreadable()),
                };
                match p.announce_sealing_key(&agent, &body, &actor).await {
                    Ok(()) => no_content(),
                    Err(refusal) => refusal_response(refusal),
                }
            }
        },
    ));

    // 3. GET /api/v1/agent/jobs
    let p = protocol.clone();
    let poll = poller;
    entries.push(Route::get("/api/v1/agent/jobs").requires(Access::AgentKey).names_no_target().handler(
        move |caller: Caller, RawQuery(query): RawQuery| {
            let p = p.clone();
            let poll = poll.clone();
            async move {
                let agent = match authenticate(&caller, &p).await {
                    Ok(a) => a,
                    Err(p) => return p.into_response(),
                };
                let wait = parse_wait(query.as_deref());
                let limit = concurrency::effective(agent.max_concurrent.map(i64::from)).to_string();

                match poll.claim(&agent, wait).await {
                    Ok(Some(task)) => {
                        let mut resp = ok(&task.assigned());
                        if let Ok(val) = HeaderValue::from_str(&limit) {
                            resp.headers_mut().insert(concurrency::HEADER, val);
                        }
                        resp
                    }
                    Ok(None) => {
                        let mut resp = no_content();
                        if let Ok(val) = HeaderValue::from_str(&limit) {
                            resp.headers_mut().insert(concurrency::HEADER, val);
                        }
                        resp
                    }
                    Err(err) => {
                        let problem: Problem = err.into();
                        let mut resp = problem.into_response();
                        if let Ok(val) = HeaderValue::from_str(&limit) {
                            resp.headers_mut().insert(concurrency::HEADER, val);
                        }
                        resp
                    }
                }
            }
        },
    ));

    // 4. POST /api/v1/agent/jobs/{scanId}/heartbeat
    let p = protocol.clone();
    entries.push(
        Route::post("/api/v1/agent/jobs/{scanId}/heartbeat").requires(Access::AgentKey).names_no_target().handler(
            move |caller: Caller, Path(scan_id): Path<i64>| {
                let p = p.clone();
                async move {
                    let agent = match authenticate(&caller, &p).await {
                        Ok(a) => a,
                        Err(p) => return p.into_response(),
                    };
                    match p.renew_lease(&agent, scan_id).await {
                        Ok(true) => no_content(),
                        Ok(false) => Problem::handler(
                            StatusCode::CONFLICT,
                            "This scan is no longer yours: its lease was taken over.",
                        )
                        .into_response(),
                        Err(err) => {
                            Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                        }
                    }
                }
            },
        ),
    );

    // 5. POST /api/v1/agent/jobs/{scanId}/result
    let p = protocol.clone();
    entries.push(
        Route::post("/api/v1/agent/jobs/{scanId}/result").requires(Access::AgentKey).names_no_target().handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Path(scan_id): Path<i64>,
                  request: Request| {
                let p = p.clone();
                async move {
                    let agent = match authenticate(&caller, &p).await {
                        Ok(a) => a,
                        Err(p) => return p.into_response(),
                    };
                    let actor = unnamed_actor(&address, &headers);
                    let signature = headers.get(AGENT_SIGNATURE_HEADER).and_then(|v| v.to_str().ok());
                    let body = match read_bytes(request).await {
                        Ok(b) => b,
                        Err(p) => return p.into_response(),
                    };
                    match p.submit_result(&agent, scan_id, &body, signature, &actor).await {
                        Ok(()) => {
                            let mut map = std::collections::HashMap::new();
                            map.insert("accepted", true);
                            ok(&map)
                        }
                        Err(refusal) => refusal_response(refusal),
                    }
                }
            },
        ),
    );

    // 6. POST /api/v1/agent/jobs/{scanId}/failure
    let p = protocol.clone();
    entries.push(
        Route::post("/api/v1/agent/jobs/{scanId}/failure").requires(Access::AgentKey).names_no_target().handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Path(scan_id): Path<i64>,
                  request: Request| {
                let p = p.clone();
                async move {
                    let agent = match authenticate(&caller, &p).await {
                        Ok(a) => a,
                        Err(p) => return p.into_response(),
                    };
                    let actor = unnamed_actor(&address, &headers);
                    let signature = headers.get(AGENT_SIGNATURE_HEADER).and_then(|v| v.to_str().ok());
                    let body = match read_bytes(request).await {
                        Ok(b) => b,
                        Err(p) => return p.into_response(),
                    };
                    match p.report_failure(&agent, scan_id, &body, signature, &actor).await {
                        Ok(answer) => {
                            let retry_at_str = answer.retry_at.map(vectispire_protocol::server::iso_instant);
                            ok(&FailureReportResponse {
                                retried: answer.retried,
                                attempt: answer.attempt,
                                max_attempts: answer.max_attempts,
                                permanent: answer.permanent,
                                retry_at: retry_at_str,
                            })
                        }
                        Err(refusal) => refusal_response(refusal),
                    }
                }
            },
        ),
    );

    // 7. GET /api/v1/agent/rules/{hash}
    let p = protocol.clone();
    entries.push(Route::get("/api/v1/agent/rules/{hash}").requires(Access::AgentKey).names_no_target().handler(
        move |caller: Caller, Path(hash): Path<String>| {
            let p = p.clone();
            async move {
                if let Err(p) = authenticate(&caller, &p).await {
                    return p.into_response();
                }
                match p.rule_set(&hash).await {
                    Ok(Some(files)) => ok(&RuleSetResponse { content_hash: hash, files }),
                    Ok(None) => Problem::handler(StatusCode::NOT_FOUND, format!("No rule set with hash {hash}."))
                        .into_response(),
                    Err(err) => Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
                }
            }
        },
    ));

    // 8. GET /api/v1/agent/plugins/{id}/{digest}
    let p = protocol;
    entries.push(
        Route::get("/api/v1/agent/plugins/{id}/{digest}").requires(Access::AgentKey).names_no_target().handler(
            move |caller: Caller, Path((id, digest)): Path<(String, String)>| {
                let p = p.clone();
                async move {
                    if let Err(p) = authenticate(&caller, &p).await {
                        return p.into_response();
                    }
                    match p.plugin(&id, &digest).await {
                        Ok(Some(manifest)) => ok(&manifest),
                        Ok(None) => {
                            Problem::handler(StatusCode::NOT_FOUND, format!("No plugin {id} with manifest {digest}."))
                                .into_response()
                        }
                        Err(err) => {
                            Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                        }
                    }
                }
            },
        ),
    );

    entries
}

async fn authenticate(caller: &Caller, protocol: &AgentProtocolService) -> Result<AuthenticatedAgent, Problem> {
    let agent_name = match &caller.0.credential {
        Credential::Agent { agent } => agent,
        _ => {
            return Err(Problem::handler(
                StatusCode::UNAUTHORIZED,
                "API key absent, invalid, or without the \"agent\" scope.",
            ));
        }
    };
    protocol.authenticate_agent(agent_name).await.map_err(|refusal| {
        let status = StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Problem::handler(status, refusal.reason)
    })
}

fn unnamed_actor(address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: None,
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

fn refusal_response(refusal: RouteRefusal) -> Response {
    let status = StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Problem::handler(status, refusal.reason).into_response()
}

fn parse_wait(raw: Option<&str>) -> i32 {
    let Some(query) = raw else { return 0 };
    for pair in query.split('&') {
        if let Some(("wait", v)) = pair.split_once('=') {
            return v.parse::<i32>().unwrap_or(0);
        }
    }
    0
}

async fn read_bytes(request: Request) -> Result<Vec<u8>, Problem> {
    axum::body::to_bytes(request.into_body(), 50 * 1024 * 1024)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| Problem::handler(StatusCode::BAD_REQUEST, "The request body could not be read."))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloResponse {
    id: uuid::Uuid,
    name: String,
    contract_version: String,
    max_concurrent: i32,
    credentials_mode: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleSetResponse {
    content_hash: String,
    files: Vec<vectispire_protocol::StoredFile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailureReportResponse {
    retried: bool,
    attempt: i32,
    max_attempts: i32,
    permanent: bool,
    retry_at: Option<String>,
}
