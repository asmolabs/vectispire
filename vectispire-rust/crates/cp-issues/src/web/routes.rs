//! HTTP routes for the issues module:
//! - 5 issue backlog & triage routes under `/api/v1/issues`
//! - 3 history routes under `/api/v1/history/repositories`
//! - 2 exceptions register & review routes under `/api/v1/exceptions`

use std::sync::Arc;

use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{ApiKeyScope, Caller, ClientAddress, JsonBody, Problem, Scoped};

use super::read;
use crate::Issues;
use crate::decision::{Caller as DecisionCaller, Decision};
use crate::error::IssueError;
use crate::query::{BacklogQuery, IssueQueryService};
use crate::triage::ReviewOutcome;

#[allow(clippy::result_large_err)]
fn allowance(scope: CallerScope) -> Result<Allowance, Response> {
    scope.map_err(|_| {
        Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "Could not resolve caller visibility").into_response()
    })
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

fn decision_caller(
    Caller(principal): &Caller,
    address: &ClientAddress,
    headers: &HeaderMap,
    allow: Allowance,
) -> DecisionCaller {
    DecisionCaller {
        username: principal.account.as_ref().map(|a| a.username.clone()),
        role: principal.account.as_ref().and_then(|a| a.role),
        visibility: allow.visibility,
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
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
            Err(err) => return IssueError::from(err).into_response(),
        }
    };
}

#[derive(Debug, Deserialize)]
pub struct TriageRequestDto {
    pub status: Option<String>,
    pub justification: Option<String>,
    pub comment: Option<String>,
    #[serde(rename = "expires_in_days")]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AttachTicketRequestDto {
    pub reference: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkTriageRequestDto {
    /// A `null` among them is read, and refused in the selection's terms — Java's `triageMany` — rather than as a body
    /// that cannot be read.
    pub ids: Option<Vec<Option<i64>>>,
    pub status: Option<String>,
    pub justification: Option<String>,
    pub comment: Option<String>,
    #[serde(rename = "expires_in_days")]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ReviewRequestDto {
    pub outcome: Option<String>,
    pub comment: Option<String>,
    #[serde(rename = "new_expiry")]
    pub new_expiry: Option<String>,
}

pub fn routes(issues: Arc<Issues>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    issues_routes(&issues, &mut entries);
    history_routes(&issues, &mut entries);
    exceptions_routes(&issues, &mut entries);
    entries
}

fn issues_routes(issues: &Arc<Issues>, entries: &mut Vec<RouteEntry>) {
    // 1. GET /api/v1/issues
    let iss = issues.clone();
    entries.push(
        Route::get("/api/v1/issues").requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
            move |_caller: Caller,
                  _address: ClientAddress,
                  _headers: HeaderMap,
                  _method: Method,
                  _uri: Uri,
                  Scoped(scope): Scoped<CallerScope>,
                  RawQuery(query): RawQuery| {
                let iss = iss.clone();
                async move {
                    let allow = match allowance(scope) {
                        Ok(a) => a,
                        Err(resp) => return resp,
                    };
                    let q = query.as_deref();
                    let state = read::query_string(q, "state");
                    let severity = read::query_string(q, "severity");
                    let type_ = read::query_string(q, "type");
                    let triage_status = read::query_string(q, "triage_status");
                    let repository_id = read_param!(read::query_long(q, "repository_id"));
                    let container_id = read_param!(read::query_long(q, "container_id"));
                    let project_id = read_param!(read::query_long(q, "project_id"));
                    let solution_id = read_param!(read::query_long(q, "solution_id"));
                    let only_direct = read_param!(read::query_bool(q, "only_direct", false));
                    let only_kev = read_param!(read::query_bool(q, "is_kev", false));
                    let overdue = read_param!(read::query_bool(q, "overdue", false));
                    let unsettled = read_param!(read::query_bool(q, "unsettled", false));
                    let search = read::query_string(q, "search");
                    let identifier = read::query_string(q, "identifier");
                    let limit_param = read_param!(read::query_int(q, "limit")).unwrap_or(50);
                    let offset_param = read_param!(read::query_int(q, "offset")).unwrap_or(0);
                    let owasp_category = read::query_string(q, "owasp_category");
                    let open_at = read::query_string(q, "open_at");
                    let first_seen_from = read::query_string(q, "first_seen_from");
                    let first_seen_to = read::query_string(q, "first_seen_to");
                    let resolved_from = read::query_string(q, "resolved_from");
                    let resolved_to = read::query_string(q, "resolved_to");
                    let reopened_from = read::query_string(q, "reopened_from");
                    let reopened_to = read::query_string(q, "reopened_to");

                    let limit = if limit_param <= 0 {
                        50
                    } else {
                        usize::try_from(limit_param).unwrap_or(50).min(IssueQueryService::MAX_PAGE_SIZE)
                    };
                    let offset = if offset_param <= 0 { 0 } else { usize::try_from(offset_param).unwrap_or(0) };

                    let query = BacklogQuery {
                        state,
                        severity,
                        type_,
                        triage_status,
                        repository_id,
                        container_id,
                        project_id,
                        solution_id,
                        only_direct,
                        only_kev,
                        overdue,
                        unsettled,
                        search,
                        identifier,
                        limit,
                        offset,
                        owasp_category,
                        open_at,
                        first_seen_from,
                        first_seen_to,
                        resolved_from,
                        resolved_to,
                        reopened_from,
                        reopened_to,
                    };

                    let page = attempt!(iss.queries().page(query, &allow.visibility).await);
                    json_response(StatusCode::OK, &page)
                }
            },
        ),
    );

    // 2. GET /api/v1/issues/{id}
    let iss = issues.clone();
    entries.push(
        Route::get("/api/v1/issues/{id}")
            .requires(Access::Account)
            .scoped()
            .accepts_api_key(ApiKeyScope::Read)
            .handler(
                move |_caller: Caller,
                      _address: ClientAddress,
                      _headers: HeaderMap,
                      _method: Method,
                      _uri: Uri,
                      Path(raw_id): Path<String>,
                      Scoped(scope): Scoped<CallerScope>| {
                    let iss = iss.clone();
                    async move {
                        let allow = match allowance(scope) {
                            Ok(a) => a,
                            Err(resp) => return resp,
                        };
                        let id = read_param!(read::path_long("id", &raw_id));
                        let detail = attempt!(iss.queries().detail(id, &allow.visibility).await);
                        json_response(StatusCode::OK, &detail)
                    }
                },
            ),
    );

    // 3. POST /api/v1/issues/{id}/triage
    let iss = issues.clone();
    entries.push(Route::post("/api/v1/issues/{id}/triage").requires(Access::WriteAccount).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Path(raw_id): Path<String>,
              Scoped(scope): Scoped<CallerScope>,
              JsonBody(body): JsonBody<TriageRequestDto>| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let id = read_param!(read::path_long("id", &raw_id));
                let d_caller = decision_caller(&caller, &address, &headers, allow);
                let decision = Decision {
                    status: body.status,
                    justification: body.justification,
                    comment: body.comment,
                    expires_in_days: body.expires_in_days,
                };
                let view = attempt!(iss.decisions().triage(id, decision, d_caller).await);
                json_response(StatusCode::OK, &view)
            }
        },
    ));

    // 4. PUT /api/v1/issues/{id}/ticket
    let iss = issues.clone();
    entries.push(Route::put("/api/v1/issues/{id}/ticket").requires(Access::WriteAccount).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Path(raw_id): Path<String>,
              Scoped(scope): Scoped<CallerScope>,
              JsonBody(body): JsonBody<AttachTicketRequestDto>| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let id = read_param!(read::path_long("id", &raw_id));
                let d_caller = decision_caller(&caller, &address, &headers, allow);
                let view = attempt!(iss.decisions().attach_ticket(id, body.reference, body.url, d_caller).await);
                json_response(StatusCode::OK, &view)
            }
        },
    ));

    // 5. POST /api/v1/issues/triage
    let iss = issues.clone();
    entries.push(Route::post("/api/v1/issues/triage").requires(Access::WriteAccount).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              JsonBody(body): JsonBody<BulkTriageRequestDto>| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let d_caller = decision_caller(&caller, &address, &headers, allow);
                let Some(ids) = body.ids.unwrap_or_default().into_iter().collect::<Option<Vec<i64>>>() else {
                    return IssueError::InvalidTriage("Every selected issue needs an identifier.".to_owned())
                        .into_response();
                };
                let decision = Decision {
                    status: body.status,
                    justification: body.justification,
                    comment: body.comment,
                    expires_in_days: body.expires_in_days,
                };
                let views = attempt!(iss.decisions().triage_many(&ids, decision, d_caller).await);
                json_response(StatusCode::OK, &views)
            }
        },
    ));
}

fn history_routes(issues: &Arc<Issues>, entries: &mut Vec<RouteEntry>) {
    // 6. GET /api/v1/history/repositories
    let iss = issues.clone();
    entries.push(Route::get("/api/v1/history/repositories").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let q = query.as_deref();
                let limit = read_param!(read::query_int(q, "limit")).map(i64::from);
                let offset = read_param!(read::query_int(q, "offset")).map(i64::from);

                let repos = attempt!(iss.history().repositories(&allow.visibility, limit, offset).await);
                json_response(StatusCode::OK, &repos)
            }
        },
    ));

    // 7. GET /api/v1/history/repositories/{id}
    let iss = issues.clone();
    entries.push(Route::get("/api/v1/history/repositories/{id}").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Path(raw_id): Path<String>,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let id = read_param!(read::path_long("id", &raw_id));
                let limit = read_param!(read::query_int(query.as_deref(), "limit"))
                    .and_then(|v| usize::try_from(v).ok())
                    .unwrap_or(50);

                let dossier = attempt!(iss.history().dossier(id, limit, &allow.visibility).await);
                json_response(StatusCode::OK, &dossier)
            }
        },
    ));

    // 8. GET /api/v1/history/repositories/{id}/export.csv
    let iss = issues.clone();
    entries.push(
        Route::get("/api/v1/history/repositories/{id}/export.csv").requires(Access::Account).scoped().handler(
            move |_caller: Caller,
                  _address: ClientAddress,
                  _headers: HeaderMap,
                  _method: Method,
                  _uri: Uri,
                  Path(raw_id): Path<String>,
                  Scoped(scope): Scoped<CallerScope>| {
                let iss = iss.clone();
                async move {
                    let allow = match allowance(scope) {
                        Ok(a) => a,
                        Err(resp) => return resp,
                    };
                    let id = read_param!(read::path_long("id", &raw_id));
                    let csv = attempt!(iss.history().csv(id, &allow.visibility).await);
                    let filename = format!("vectispire-history-{id}.csv");
                    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                        .unwrap_or(HeaderValue::from_static("attachment"));

                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, HeaderValue::from_static("text/csv")),
                            (header::CONTENT_DISPOSITION, disposition),
                        ],
                        csv,
                    )
                        .into_response()
                }
            },
        ),
    );
}

fn exceptions_routes(issues: &Arc<Issues>, entries: &mut Vec<RouteEntry>) {
    // 9. GET /api/v1/exceptions
    let iss = issues.clone();
    entries.push(Route::get("/api/v1/exceptions").requires(Access::Account).scoped().handler(
        move |_caller: Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              RawQuery(query): RawQuery| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let q = query.as_deref();
                let limit =
                    read_param!(read::query_int(q, "limit")).and_then(|v| usize::try_from(v).ok()).unwrap_or(200);
                let cursor = read::query_string(q, "cursor");

                let reg = attempt!(iss.exceptions().register(limit, cursor.as_deref(), &allow.visibility).await);
                json_response(StatusCode::OK, &reg)
            }
        },
    ));

    // 10. POST /api/v1/exceptions/{issueId}/reviews
    let iss = issues.clone();
    entries.push(Route::post("/api/v1/exceptions/{issueId}/reviews").requires(Access::SecurityLead).scoped().handler(
        move |Caller(principal): Caller,
              _address: ClientAddress,
              _headers: HeaderMap,
              _method: Method,
              _uri: Uri,
              Path(raw_id): Path<String>,
              Scoped(scope): Scoped<CallerScope>,
              JsonBody(body): JsonBody<ReviewRequestDto>| {
            let iss = iss.clone();
            async move {
                let allow = match allowance(scope) {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };
                let issue_id = read_param!(read::path_long("issueId", &raw_id));

                // What Jackson refuses before Java's controller runs — an outcome it does not know, a date it cannot
                // read — is refused here, as a body that cannot be read. A missing outcome is not: the service asks
                // for it after the role and the issue's visibility, so a governor's refusal, and a hidden issue's
                // 404, do not depend on the body (Java's ExceptionReviewService).
                let outcome = match body.outcome.as_deref() {
                    Some(raw) => match ReviewOutcome::parse(raw) {
                        Some(outcome) => Some(outcome),
                        None => {
                            return Problem::handler(StatusCode::BAD_REQUEST, vectispire_cp_http::extract::UNREADABLE)
                                .into_response();
                        }
                    },
                    None => None,
                };

                let new_expiry = match body.new_expiry.as_deref() {
                    Some(raw) => match OffsetDateTime::parse(raw, &Rfc3339) {
                        Ok(dt) => Some(dt),
                        Err(_) => {
                            return Problem::handler(StatusCode::BAD_REQUEST, vectispire_cp_http::extract::UNREADABLE)
                                .into_response();
                        }
                    },
                    None => None,
                };

                let reviewer = principal.account.as_ref().and_then(|a| a.role.map(|role| (a.username.as_str(), role)));

                let reg = attempt!(
                    iss.reviews()
                        .review(issue_id, outcome, body.comment.as_deref(), reviewer, new_expiry, &allow.visibility,)
                        .await
                );
                json_response(StatusCode::OK, &reg)
            }
        },
    ));
}
