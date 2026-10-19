//! Routes for Semgrep rule sets — `RuleSetsController`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Path, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, JsonBody, Problem};

use crate::ruleset::UploadedFile;
use crate::service::{RuleCoverageService, RuleSetAdministrationService, ServiceError};

/// Constructs the route entries for `RuleSetsController`.
pub fn routes(admin: Arc<RuleSetAdministrationService>, coverage: Arc<RuleCoverageService>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    // 1. GET /api/v1/rule-sets
    let a = admin.clone();
    entries.push(Route::get("/api/v1/rule-sets").requires(Access::GovernanceRead).names_no_target().handler(
        move || {
            let a = a.clone();
            async move {
                match a.list().await {
                    Ok(list) => ok(&list),
                    Err(err) => err_response(err, "/api/v1/rule-sets"),
                }
            }
        },
    ));

    // 2. POST /api/v1/rule-sets
    let a = admin.clone();
    entries.push(Route::post("/api/v1/rule-sets").requires(Access::SecurityLead).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let a = a.clone();
            async move {
                let actor = actor(&caller, &address, &headers);
                let body = match read_json::<UploadRequest>(request).await {
                    Ok(b) => b,
                    Err(p) => return p.into_response(),
                };
                let name = body.name.unwrap_or_default();
                let files = body.files.unwrap_or_default();
                match a.upload(&files, &name, &actor).await {
                    Ok(stored) => ok(&Uploaded {
                        id: stored.id,
                        content_hash: stored.content_hash,
                        rule_count: stored.rule_count,
                        file_count: stored.file_count,
                    }),
                    Err(err) => err_response(err, "/api/v1/rule-sets"),
                }
            }
        },
    ));

    // 3. GET /api/v1/rule-sets/coverage
    let c = coverage.clone();
    entries.push(Route::get("/api/v1/rule-sets/coverage").requires(Access::GovernanceRead).names_no_target().handler(
        move || {
            let c = c.clone();
            async move {
                match c.assess().await {
                    Ok(assessment) => ok(&assessment),
                    Err(err) => err_response(err, "/api/v1/rule-sets/coverage"),
                }
            }
        },
    ));

    // 4. GET /api/v1/rule-sets/catalogue
    let a = admin.clone();
    entries.push(Route::get("/api/v1/rule-sets/catalogue").requires(Access::SecurityLead).names_no_target().handler(
        move || {
            let a = a.clone();
            async move {
                match a.fetcher().preview() {
                    Ok(preview) => ok(&preview),
                    Err(err) => Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, err.0)
                        .at("/api/v1/rule-sets/catalogue")
                        .into_response(),
                }
            }
        },
    ));

    // 5. POST /api/v1/rule-sets/catalogue
    let a = admin.clone();
    entries.push(Route::post("/api/v1/rule-sets/catalogue").requires(Access::SecurityLead).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let a = a.clone();
            async move {
                let actor = actor(&caller, &address, &headers);
                let body = match read_json::<CatalogueRequest>(request).await {
                    Ok(b) => b,
                    Err(p) => return p.into_response(),
                };
                let commit = body.commit.unwrap_or_default();
                let languages = body.languages.unwrap_or_default();
                let licence_sha256 = body.licence_sha256.unwrap_or_default();
                match a
                    .import_catalogue(&commit, &languages, &licence_sha256, body.include_gitleaks_duplicates, &actor)
                    .await
                {
                    Ok(stored) => ok(&Uploaded {
                        id: stored.id,
                        content_hash: stored.content_hash,
                        rule_count: stored.rule_count,
                        file_count: stored.file_count,
                    }),
                    Err(err) => err_response(err, "/api/v1/rule-sets/catalogue"),
                }
            }
        },
    ));

    // 6. GET /api/v1/rule-sets/{id}/impact
    let a = admin.clone();
    entries.push(
        Route::get("/api/v1/rule-sets/{id}/impact").requires(Access::GovernanceRead).names_no_target().handler(
            move |Path(id): Path<i64>| {
                let a = a.clone();
                async move {
                    match a.impact(id).await {
                        Ok(impact) => ok(&impact),
                        Err(err) => err_response(err, &format!("/api/v1/rule-sets/{id}/impact")),
                    }
                }
            },
        ),
    );

    // 7. POST /api/v1/rule-sets/{id}/activate
    let a = admin.clone();
    entries.push(
        Route::post("/api/v1/rule-sets/{id}/activate").requires(Access::SecurityLead).names_no_target().handler(
            move |Path(id): Path<i64>, caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
                let a = a.clone();
                async move {
                    let actor = actor(&caller, &address, &headers);
                    let body: Option<ActivateRequest> = read_optional_json(request).await;
                    let (note, accept_losing) = match body {
                        Some(b) => (b.note, b.accept_losing),
                        None => (None, None),
                    };
                    let path = format!("/api/v1/rule-sets/{id}/activate");

                    match a.activate(id, note.as_deref(), accept_losing, &actor).await {
                        Ok(activated) => ok(&json!({
                            "id": activated.id,
                            "contentHash": activated.content_hash
                        })),
                        Err(err) => err_response(err, &path),
                    }
                }
            },
        ),
    );

    // 8. GET /api/v1/rule-sets/deactivate/impact
    let a = admin.clone();
    entries.push(
        Route::get("/api/v1/rule-sets/deactivate/impact").requires(Access::GovernanceRead).names_no_target().handler(
            move || {
                let a = a.clone();
                async move {
                    match a.deactivation_impact().await {
                        Ok(impact) => ok(&impact),
                        Err(err) => err_response(err, "/api/v1/rule-sets/deactivate/impact"),
                    }
                }
            },
        ),
    );

    // 9. POST /api/v1/rule-sets/deactivate
    let a = admin.clone();
    entries.push(Route::post("/api/v1/rule-sets/deactivate").requires(Access::SecurityLead).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let a = a.clone();
            async move {
                let actor = actor(&caller, &address, &headers);
                let body: Option<DeactivateRequest> = read_optional_json(request).await;
                let accept_losing = body.and_then(|b| b.accept_losing);
                let path = "/api/v1/rule-sets/deactivate";

                match a.deactivate(accept_losing, &actor).await {
                    Ok(()) => ok(&json!({ "active": null })),
                    Err(err) => err_response(err, path),
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

fn err_response(err: ServiceError, path: &str) -> Response {
    match err {
        ServiceError::NotFound(id) => {
            Problem::handler(StatusCode::NOT_FOUND, format!("No rule set with id {id}.")).at(path).into_response()
        }
        ServiceError::InvalidInput(detail) => {
            Problem::handler(StatusCode::BAD_REQUEST, detail).at(path).into_response()
        }
        ServiceError::RuleSetLosesIssues { affected_issues, losing_issues, detail } => {
            Problem::handler(StatusCode::CONFLICT, detail)
                .at(path)
                .caused_by("rule-set-activation-loses-issues")
                .with("affectedIssues", affected_issues)
                .with("losingIssues", losing_issues)
                .into_response()
        }
        ServiceError::Store(e) => {
            Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).at(path).into_response()
        }
        ServiceError::Other(e) => Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, e).at(path).into_response(),
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, Problem> {
    JsonBody::<T>::from_request(request, &()).await.map(|JsonBody(body)| body)
}

async fn read_optional_json<T: serde::de::DeserializeOwned>(request: Request) -> Option<T> {
    JsonBody::<T>::from_request(request, &()).await.ok().map(|JsonBody(body)| body)
}

#[derive(Deserialize)]
struct UploadRequest {
    name: Option<String>,
    files: Option<Vec<UploadedFile>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Uploaded {
    id: i64,
    content_hash: String,
    rule_count: i32,
    file_count: i32,
}

#[derive(Deserialize)]
struct CatalogueRequest {
    commit: Option<String>,
    languages: Option<Vec<String>>,
    #[serde(rename = "licence_sha256")]
    licence_sha256: Option<String>,
    #[serde(rename = "includeGitleaksDuplicates")]
    include_gitleaks_duplicates: Option<bool>,
}

#[derive(Deserialize)]
struct ActivateRequest {
    note: Option<String>,
    #[serde(rename = "acceptLosing")]
    accept_losing: Option<i64>,
}

#[derive(Deserialize)]
struct DeactivateRequest {
    #[serde(rename = "acceptLosing")]
    accept_losing: Option<i64>,
}
