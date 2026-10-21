//! HTTP routes for the gate module:
//! - `POST /api/v1/gate`: `evaluate`
//! - `GET /api/v1/gate/verdicts`: `register_2`
//! - `GET /api/v1/security/overview`: `overview`
//! - `GET /api/v1/gate/policies`: `list_21`
//! - `PUT /api/v1/gate/policies/global`: `storeGlobal`
//! - `PUT /api/v1/gate/policies/{kind}/{id}`: `storeForTarget`
//! - `DELETE /api/v1/gate/policies/{kind}/{id}`: `clear`

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
use vectispire_cp_http::{ApiKeyScope, Caller as HttpCaller, ClientAddress, JsonBody, Problem, Scoped};

use super::read;
use super::views::{
    GatePolicyView, GateRequest, GateResponse, PoliciesResponse, PolicyRequest, RegisteredVerdict,
    SecurityOverviewView, VerdictRegister,
};
use crate::fields::GatePolicyFields;
use crate::service::{Caller, GatePolicyAdministrationService, GateRegisterService, GateService, PolicyScope};

#[allow(clippy::result_large_err)]
fn allowance(scope: CallerScope) -> Result<Allowance, Response> {
    scope.map_err(|_| {
        Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "Could not resolve caller visibility").into_response()
    })
}

fn request_actor(caller: &HttpCaller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
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

/// Constructs all route entries for the Gate module.
pub fn routes(
    gate: Arc<GateService>,
    admin: Arc<GatePolicyAdministrationService>,
    verdicts: Arc<GateRegisterService>,
) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    // 1. POST /api/v1/gate — evaluate
    let g = gate.clone();
    entries.push(
        Route::post("/api/v1/gate").requires(Access::WriteAccount).accepts_api_key(ApiKeyScope::Scan).scoped().handler(
            move |caller: HttpCaller,
                  address: ClientAddress,
                  _headers: HeaderMap,
                  Scoped(scope): Scoped<CallerScope>,
                  JsonBody(body): JsonBody<GateRequest>| {
                let gate = g.clone();
                async move {
                    let allow = match allowance(scope) {
                        Ok(a) => a,
                        Err(r) => return r,
                    };
                    let target = match GateService::verdict_target(body.repository_id, body.container_id) {
                        Ok(t) => t,
                        Err(err) => return err.into_response(),
                    };
                    if let Err(err) = vectispire_cp_access::rows::require_visible(target, &allow.visibility) {
                        return Problem::handler(StatusCode::NOT_FOUND, err.message).into_response();
                    }
                    let fields = GatePolicyFields::new(
                        body.fail_on_severity,
                        body.fail_on_kev,
                        body.fixable_only,
                        body.include_triaged,
                        body.include_ai_review,
                        None,
                        body.include_plugins,
                    );
                    let requested = match fields.as_request() {
                        Ok(r) => r,
                        Err(err) => return err.into_response(),
                    };
                    let gate_caller = Caller { principal: caller.0.actor(), ip_address: Some(address.0) };
                    match gate.evaluate_and_record(target, &requested, &gate_caller).await {
                        Ok(decision) => {
                            let resp = GateResponse::new(&decision.verdict, &decision.policy);
                            ok(&resp)
                        }
                        Err(err) => err.into_response(),
                    }
                }
            },
        ),
    );

    // 2. GET /api/v1/gate/verdicts — register_2
    let v = verdicts.clone();
    entries.push(
        Route::get("/api/v1/gate/verdicts")
            .requires(Access::Account)
            .accepts_api_key(ApiKeyScope::Read)
            .scoped()
            .handler(
                move |_caller: HttpCaller,
                      _address: ClientAddress,
                      _headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      RawQuery(query): RawQuery| {
                    let verdicts = v.clone();
                    async move {
                        let allow = match allowance(scope) {
                            Ok(a) => a,
                            Err(r) => return r,
                        };
                        let limit = match read::query_int(query.as_deref(), "limit") {
                            Ok(l) => l.unwrap_or(100),
                            Err(p) => return p.into_response(),
                        };
                        let cursor = read::query_string(query.as_deref(), "cursor");
                        match verdicts.page(&allow.visibility, limit, cursor.as_deref()).await {
                            Ok(page) => {
                                let reg = VerdictRegister {
                                    verdicts: page.visible.iter().map(RegisteredVerdict::of).collect(),
                                    passed: page.passed,
                                    refused: page.refused,
                                    next_cursor: page.next_cursor,
                                };
                                ok(&reg)
                            }
                            Err(err) => err.into_response(),
                        }
                    }
                },
            ),
    );

    // 3. GET /api/v1/security/overview — overview
    let g = gate.clone();
    entries.push(Route::get("/api/v1/security/overview").requires(Access::Account).scoped().handler(
        move |_caller: HttpCaller, _address: ClientAddress, _headers: HeaderMap, Scoped(scope): Scoped<CallerScope>| {
            let gate = g.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(r) => return r,
                };
                match gate.overview(&allow.visibility).await {
                    Ok(overview) => {
                        let view = SecurityOverviewView::of(&overview);
                        ok(&view)
                    }
                    Err(err) => err.into_response(),
                }
            }
        },
    ));

    // 4. GET /api/v1/gate/policies — list_21
    let g = gate.clone();
    entries.push(Route::get("/api/v1/gate/policies").requires(Access::GovernanceRead).names_no_target().handler(
        move || {
            let gate = g.clone();
            async move {
                match gate.list_policies_with_names().await {
                    Ok(list) => {
                        let policies =
                            list.iter().map(|(policy, name)| GatePolicyView::of(policy, name.clone())).collect();
                        let resp = PoliciesResponse { policies, built_in: GatePolicyView::built_in() };
                        ok(&resp)
                    }
                    Err(err) => err.into_response(),
                }
            }
        },
    ));

    // 5. PUT /api/v1/gate/policies/global — storeGlobal
    let a = admin.clone();
    entries.push(Route::put("/api/v1/gate/policies/global").requires(Access::SecurityLead).names_no_target().handler(
        move |caller: HttpCaller,
              address: ClientAddress,
              headers: HeaderMap,
              JsonBody(body): JsonBody<PolicyRequest>| {
            let admin = a.clone();
            async move {
                let actor = request_actor(&caller, &address, &headers);
                let fields = GatePolicyFields::new(
                    body.fail_on_severity,
                    body.fail_on_kev,
                    body.fixable_only,
                    body.include_triaged,
                    body.include_ai_review,
                    body.fail_on_uncovered_languages,
                    body.include_plugins,
                );
                match admin.store(&PolicyScope::global(), &fields, body.note.as_deref(), &actor).await {
                    Ok(stored) => {
                        let view = GatePolicyView::of(&stored, None);
                        ok(&view)
                    }
                    Err(err) => err.into_response(),
                }
            }
        },
    ));

    // 6. PUT /api/v1/gate/policies/{kind}/{id} — storeForTarget
    let a = admin.clone();
    let g = gate.clone();
    entries.push(
        Route::put("/api/v1/gate/policies/{kind}/{id}").requires(Access::SecurityLead).names_no_target().handler(
            move |caller: HttpCaller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Path((kind, raw_id)): Path<(String, String)>,
                  JsonBody(body): JsonBody<PolicyRequest>| {
                let admin = a.clone();
                let gate = g.clone();
                async move {
                    let id = match read::path_long("id", &raw_id) {
                        Ok(i) => i,
                        Err(p) => return p.into_response(),
                    };
                    let scope = match PolicyScope::of(&kind, id) {
                        Ok(s) => s,
                        Err(err) => return err.into_response(),
                    };
                    let actor = request_actor(&caller, &address, &headers);
                    let fields = GatePolicyFields::new(
                        body.fail_on_severity,
                        body.fail_on_kev,
                        body.fixable_only,
                        body.include_triaged,
                        body.include_ai_review,
                        body.fail_on_uncovered_languages,
                        body.include_plugins,
                    );
                    match admin.store(&scope, &fields, body.note.as_deref(), &actor).await {
                        Ok(stored) => {
                            let name = gate.target_name_of_scope(&scope).await.ok().flatten();
                            let view = GatePolicyView::of(&stored, name);
                            ok(&view)
                        }
                        Err(err) => err.into_response(),
                    }
                }
            },
        ),
    );

    // 7. DELETE /api/v1/gate/policies/{kind}/{id} — clear
    let a = admin;
    entries.push(
        Route::delete("/api/v1/gate/policies/{kind}/{id}").requires(Access::SecurityLead).names_no_target().handler(
            move |caller: HttpCaller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Path((kind, raw_id)): Path<(String, String)>| {
                let admin = a.clone();
                async move {
                    let id = match read::path_long("id", &raw_id) {
                        Ok(i) => i,
                        Err(p) => return p.into_response(),
                    };
                    let scope = match PolicyScope::of(&kind, id) {
                        Ok(s) => s,
                        Err(err) => return err.into_response(),
                    };
                    let actor = request_actor(&caller, &address, &headers);
                    match admin.clear(&scope, &actor).await {
                        Ok(true) => StatusCode::NO_CONTENT.into_response(),
                        Ok(false) => {
                            Problem::handler(StatusCode::NOT_FOUND, format!("No policy stored for {kind} {id}."))
                                .into_response()
                        }
                        Err(err) => err.into_response(),
                    }
                }
            },
        ),
    );

    entries
}
