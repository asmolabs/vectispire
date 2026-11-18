//! Compliance's routes — so far `ComplianceController`'s summary and framework, `ScopeComplianceController`, and the
//! governance: `StatementOfApplicabilityController`, `CertifiedScopeController`, `ComplianceHistoryController`.
//!
//! - `GET /api/v1/compliance/summary`, `GET /api/v1/compliance/frameworks/{framework}`
//! - `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance`
//! - `GET /api/v1/compliance/soa`, `GET /api/v1/compliance/soa/{framework}`, `GET /api/v1/compliance/soa/reviews/overdue`,
//!   `PUT /api/v1/compliance/soa/{framework}/{controlId}`
//! - `GET /api/v1/compliance/scope`, `PUT /api/v1/compliance/scope/repositories/{id}`, `PUT …/containers/{id}`
//! - `GET /api/v1/compliance/history`
//!
//! Every one resolves the caller's allowance and reads only what it permits; a scope the caller sees nothing of is
//! refused as an absent one, **404 and never 403**.

use std::sync::Arc;

use crate::decisions::ComplianceFramework;
use axum::body::Body;
use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use serde::{Deserialize, Deserializer, Serialize};
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::download_guard;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{ApiKeyScope, Caller, ClientAddress, JsonBody, Problem, Scoped};
use vectispire_domain::instant::Instant;

use super::read;
use crate::certified::{CertifiedScopeService, TargetKind};
use crate::decisions::{Applicability, EvidenceSource, Implementation};
use crate::declarations::{StatementOfApplicabilityService, Submission};
use crate::error::ComplianceError;
use crate::matrix::ComplianceService;
use crate::progress::ComplianceHistoryService;
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
    pub soa: StatementOfApplicabilityService,
    pub certified: CertifiedScopeService,
    pub history: ComplianceHistoryService,
    pub grid: crate::grid::OwaspGridService,
    pub weekly: crate::weekly::OwaspWeeklyHistoryService,
    pub weekly_capture: crate::weekly_capture::OwaspWeeklyCoverageService,
    pub report: crate::review::OwaspReportService,
}

/// `DeclarationRequest`, members in the record's order; the three snake_case names are its `@JsonProperty`s.
#[derive(Debug, Deserialize)]
struct DeclarationRequest {
    applicability: Option<Applicability>,
    justification: Option<String>,
    implementation: Option<Implementation>,
    evidence_source: Option<EvidenceSource>,
    external_evidence: Option<String>,
    owner: Option<String>,
    #[serde(default, deserialize_with = "jackson_instant")]
    review_due_at: Option<Instant>,
}

/// An `Instant` as Jackson's `InstantDeserializer` reads one: ISO-8601 text, or a number of seconds from the epoch
/// whose fraction is the nanoseconds.
fn jackson_instant<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Instant>, D::Error> {
    let refused = || serde::de::Error::custom("not an instant");
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => {
            let text = text.trim();
            if text.is_empty() { Ok(None) } else { Instant::parse_java(text).map(Some).ok_or_else(refused) }
        }
        Some(serde_json::Value::Number(number)) => match number.as_i64() {
            Some(seconds) => Ok(Some(Instant::of_epoch_second(seconds))),
            None => {
                let text = number.to_string();
                let (whole, fraction) = text.split_once('.').ok_or_else(refused)?;
                let seconds: i64 = whole.parse().map_err(|_| refused())?;
                let digits: String = fraction.chars().chain(std::iter::repeat('0')).take(9).collect();
                let nano: u32 = digits.parse().map_err(|_| refused())?;
                Ok(Some(Instant { epoch_second: seconds, nano }))
            }
        },
        Some(_) => Err(refused()),
    }
}

fn request_actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(str::to_owned),
    }
}

/// `@PathVariable ComplianceFramework`: Spring's enum conversion, the constant's exact name — stricter than the
/// summary's `fromIdentifier`, as Java is.
#[allow(clippy::result_large_err)]
fn framework_named(raw: &str) -> Result<ComplianceFramework, Response> {
    ComplianceFramework::from_name(raw.trim()).ok_or_else(|| {
        Problem::handler(StatusCode::BAD_REQUEST, format!("Failed to convert 'framework' with value: '{raw}'"))
            .into_response()
    })
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
    let mut entries = governance(s);
    entries.extend(matrix(s));
    entries.extend(owasp(s));
    entries.push(report(s));
    entries
}

/// One repository's OWASP report, read. **Repositories only, and the path says so**: half the Top 10 describes code
/// and the decisions behind it, which an image does not have. The request and the PDF wait for the `ai` module.
fn report(s: &Arc<Services>) -> RouteEntry {
    read_route_of("/api/v1/repositories/{id}/owasp-review", s, async |m, allowed, raw| {
        let id = or_answer!(read::path_long("id", &raw).map_err(IntoResponse::into_response));
        answer(m.report.latest(id, &allowed.visibility).await)
    })
}

const DECLARE: &str = "/api/v1/compliance/soa/{framework}/{controlId}";

/// The statement of applicability, the certified scope and the history. **Governance reads take no API key**, and a
/// declaration names no target for a visibility to narrow — the role is the lock.
fn governance(s: &Arc<Services>) -> Vec<RouteEntry> {
    let soa_all = s.clone();
    let soa_one = s.clone();
    let overdue = s.clone();
    let declare = s.clone();
    let scope = s.clone();
    let history = s.clone();
    vec![
        Route::get("/api/v1/compliance/soa").requires(Access::GovernanceRead).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>| {
                let m = soa_all.clone();
                async move {
                    let allowed = or_answer!(allowance(scope));
                    answer(m.soa.statements(&allowed.visibility).await)
                }
            },
        ),
        Route::get("/api/v1/compliance/soa/reviews/overdue")
            .requires(Access::GovernanceRead)
            .names_no_target()
            .handler(move || {
                let m = overdue.clone();
                async move { answer(m.soa.review_overdue().await) }
            }),
        Route::get("/api/v1/compliance/soa/{framework}").requires(Access::GovernanceRead).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, Path(raw): Path<String>| {
                let m = soa_one.clone();
                async move {
                    let allowed = or_answer!(allowance(scope));
                    let framework = or_answer!(framework_named(&raw));
                    answer(m.soa.statement(framework, &allowed.visibility).await)
                }
            },
        ),
        // Every answer of this route, the refusals of its body included, through Spring's download guard: a control
        // identifier's dots read as a file extension there.
        Route::put(DECLARE).requires(Access::SecurityLead).names_no_target().handler(
            move |caller: Caller,
                  uri: Uri,
                  Path((raw, control_id)): Path<(String, String)>,
                  body: Result<JsonBody<DeclarationRequest>, Problem>| {
                let m = declare.clone();
                async move {
                    let answered = async {
                        let framework = or_answer!(framework_named(&raw));
                        let JsonBody(body) = or_answer!(body.map_err(IntoResponse::into_response));
                        // The account's username, or none: Java's `principal.user().map(username)`.
                        let actor = caller.0.account.as_ref().map(|account| account.username.clone());
                        answer(m.soa.declare(framework, &control_id, submission(body), actor.as_deref()).await)
                    }
                    .await;
                    download_guard::guard(uri.path(), DECLARE, answered)
                }
            },
        ),
        Route::get("/api/v1/compliance/scope").requires(Access::Account).scoped().handler(
            move |Scoped(caller_scope): Scoped<CallerScope>| {
                let m = scope.clone();
                async move {
                    let allowed = or_answer!(allowance(caller_scope));
                    answer(m.certified.view(&allowed.visibility).await)
                }
            },
        ),
        scope_membership("/api/v1/compliance/scope/repositories/{id}", s, TargetKind::Repository),
        scope_membership("/api/v1/compliance/scope/containers/{id}", s, TargetKind::Container),
        Route::get("/api/v1/compliance/history").requires(Access::GovernanceRead).names_no_target().handler(
            move || {
                let m = history.clone();
                async move { answer(m.history.history().await) }
            },
        ),
    ]
}

/// `setRepository` / `setContainer`: the membership set, then the scope read again over the caller's view.
fn scope_membership(path: &str, services: &Arc<Services>, kind: TargetKind) -> RouteEntry {
    let services = services.clone();
    Route::put(path).requires(Access::SecurityLead).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Scoped(scope): Scoped<CallerScope>,
              Path(raw): Path<String>,
              RawQuery(query): RawQuery| {
            let m = services.clone();
            async move {
                let allowed = or_answer!(allowance(scope));
                let id = or_answer!(read::path_long("id", &raw).map_err(IntoResponse::into_response));
                let in_scope =
                    or_answer!(read::required_bool(query.as_deref(), "in_scope").map_err(IntoResponse::into_response));
                let actor = request_actor(&caller, &address, &headers);
                if let Err(refused) = m.certified.set_in_scope(kind, id, &allowed.visibility, in_scope, &actor).await {
                    return refused.into_response();
                }
                answer(m.certified.view(&allowed.visibility).await)
            }
        },
    )
}

/// The OWASP grid: the categories now, as a spreadsheet, week by week, and a category declared. **No API key on
/// any of them.**
fn owasp(s: &Arc<Services>) -> Vec<RouteEntry> {
    let grid = s.clone();
    let csv = s.clone();
    let weekly = s.clone();
    let declare = s.clone();
    vec![
        Route::get("/api/v1/owasp/coverage").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, RawQuery(query): RawQuery| {
                let m = grid.clone();
                async move {
                    let allowed = or_answer!(allowance(scope));
                    let (project, solution) = or_answer!(scope_ids(query.as_deref()));
                    answer(m.grid.grid(project, solution, &allowed).await)
                }
            },
        ),
        Route::get("/api/v1/owasp/coverage/export.csv").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, RawQuery(query): RawQuery| {
                let m = csv.clone();
                async move {
                    let allowed = or_answer!(allowance(scope));
                    let (project, solution) = or_answer!(scope_ids(query.as_deref()));
                    let language = read::query_string(query.as_deref(), "language");
                    match m.grid.csv(project, solution, &allowed, language.as_deref()).await {
                        Ok(document) => csv_attachment(document, project, solution),
                        Err(refused) => refused.into_response(),
                    }
                }
            },
        ),
        Route::get("/api/v1/owasp/coverage/weekly").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, RawQuery(query): RawQuery| {
                let m = weekly.clone();
                async move {
                    let allowed = or_answer!(allowance(scope));
                    let (project_id, solution_id) = or_answer!(scope_ids(query.as_deref()));
                    let request = crate::weekly::Request {
                        from: read::query_string(query.as_deref(), "from"),
                        to: read::query_string(query.as_deref(), "to"),
                        project_id,
                        solution_id,
                    };
                    answer(m.weekly.weeks(&request, &allowed).await)
                }
            },
        ),
        Route::put("/api/v1/owasp/coverage/{category}/declaration")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller, Path(category): Path<String>, JsonBody(body): JsonBody<DeclarationRequest>| {
                    let m = declare.clone();
                    async move {
                        // Case-sensitive, as Java's `CATEGORIES.containsKey`: `a03` is not a category.
                        if !vectispire_domain::owasp_coverage::is_category(&category) {
                            return ComplianceError::NotFound(format!(
                                "{category} is not a category of the OWASP Top 10:2021."
                            ))
                            .into_response();
                        }
                        // The account's username, or "unknown" — this route's fallback, not the statement's null.
                        let actor =
                            caller.0.account.as_ref().map_or_else(|| "unknown".to_owned(), |a| a.username.clone());
                        answer(
                            m.soa.declare_key(crate::grid::FRAMEWORK, &category, submission(body), Some(&actor)).await,
                        )
                    }
                },
            ),
    ]
}

/// `project_id` and `solution_id`, each read before either is judged.
#[allow(clippy::result_large_err)]
fn scope_ids(query: Option<&str>) -> Result<(Option<i64>, Option<i64>), Response> {
    let project = read::query_long(query, "project_id").map_err(IntoResponse::into_response)?;
    let solution = read::query_long(query, "solution_id").map_err(IntoResponse::into_response)?;
    Ok((project, solution))
}

/// The spreadsheet as an attachment named after its scope.
fn csv_attachment(document: String, project: Option<i64>, solution: Option<i64>) -> Response {
    let filename = match (project, solution) {
        (Some(id), _) => format!("vectispire-owasp-coverage-project-{id}.csv"),
        (None, Some(id)) => format!("vectispire-owasp-coverage-solution-{id}.csv"),
        (None, None) => "vectispire-owasp-coverage.csv".to_owned(),
    };
    let mut response = Response::new(Body::from(document));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv;charset=utf-8"));
    if let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        response.headers_mut().insert(header::CONTENT_DISPOSITION, disposition);
    }
    response
}

fn submission(body: DeclarationRequest) -> Submission {
    Submission {
        applicability: body.applicability,
        justification: body.justification,
        implementation: body.implementation,
        evidence_source: body.evidence_source,
        external_evidence: body.external_evidence,
        owner: body.owner,
        review_due_at: body.review_due_at,
    }
}

/// The matrix: the summary, one framework, and a project's or a solution's reading.
fn matrix(s: &Arc<Services>) -> Vec<RouteEntry> {
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
