//! The three scan routes — `ScansController`: the history, one scan's detail, its SBOM.
//!
//! **Every one is `.scoped()`**: the chain resolves the caller's allowance — the account's grants intersected with the
//! credential's restriction — and the service applies it in the query, refusing a scan the caller may not see as the
//! absence it must read like (`Scan not found.`, 404, never 403). `tests/routes.rs` walks the router to prove it.

mod read;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, Method, StatusCode, Uri, header};
use serde::Serialize;
use time::OffsetDateTime;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{ApiKeyScope, Problem, Scoped};
use vectispire_cp_targets::naming::Names;

use crate::Scanning;
use crate::error::ScanError;
use crate::query::Detail;
use crate::views::{PluginOutcome, ScanView, examined_types};

macro_rules! read {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(problem) => return problem.into_response(),
        }
    };
}
/// The routes, each with its marker and its answer on visibility.
pub fn routes(scanning: Arc<Scanning>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    let s = scanning.clone();
    entries.push(
        Route::get("/api/v1/scans").requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
            move |method: Method, uri: Uri, Scoped(scope): Scoped<CallerScope>, RawQuery(query): RawQuery| {
                let s = s.clone();
                async move {
                    let allowance = match allowance(&method, &uri, scope) {
                        Ok(allowance) => allowance,
                        Err(refused) => return *refused,
                    };
                    let query = query.as_deref();
                    let repo = read!(read::query_long(query, "repo_id"));
                    let container = read!(read::query_long(query, "container_id"));
                    // `int limit` with its default: absent or empty is fifty.
                    let limit = read!(read::query_int(query, "limit")).unwrap_or(50);
                    let offset = read!(read::query_int(query, "offset"));
                    match s.history(&allowance.visibility, repo, container, limit, offset).await {
                        Ok(history) => ok(&history
                            .scans
                            .iter()
                            .map(|scan| ScanSummary::of(scan, &history.names))
                            .collect::<Vec<_>>()),
                        Err(error) => refuse(&method, &uri, error),
                    }
                }
            },
        ),
    );
    let s = scanning.clone();
    entries.push(
        Route::get("/api/v1/scans/{id}").requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
            move |method: Method, uri: Uri, Scoped(scope): Scoped<CallerScope>, Path(id): Path<String>| {
                let s = s.clone();
                async move {
                    let allowance = match allowance(&method, &uri, scope) {
                        Ok(allowance) => allowance,
                        Err(refused) => return *refused,
                    };
                    let id = read!(read::path_long("id", &id));
                    match s.detail(id, &allowance.visibility).await {
                        Ok(detail) => match ScanDetail::of(&detail) {
                            Ok(body) => ok(&body),
                            Err(error) => refuse(&method, &uri, error),
                        },
                        Err(error) => refuse(&method, &uri, error),
                    }
                }
            },
        ),
    );
    let s = scanning;
    entries.push(
        Route::get("/api/v1/scans/{id}/sbom")
            .requires(Access::Account)
            .scoped()
            .accepts_api_key(ApiKeyScope::Read)
            .handler(move |method: Method, uri: Uri, Scoped(scope): Scoped<CallerScope>, Path(id): Path<String>| {
                let s = s.clone();
                async move {
                    let allowance = match allowance(&method, &uri, scope) {
                        Ok(allowance) => allowance,
                        Err(refused) => return *refused,
                    };
                    let id = read!(read::path_long("id", &id));
                    match s.sbom(id, &allowance.visibility).await {
                        Ok(document) => sbom(id, document),
                        Err(error) => refuse(&method, &uri, error),
                    }
                }
            }),
    );
    entries
}

#[derive(Debug, thiserror::Error)]
#[error("the caller's visibility could not be resolved")]
struct NoAllowance;

/// The allowance the chain resolved, or the 500 a failure to resolve one is — **never an empty allowance**, which would
/// answer a 404 or an empty history for what is a failure of the server (decision 0007).
fn allowance(method: &Method, uri: &Uri, scope: CallerScope) -> Result<Allowance, Box<Response>> {
    scope.map_err(|_| Box::new(refuse(method, uri, ScanError::unexpected(NoAllowance))))
}

/// A refusal as `ApiExceptionHandler` answers it; an unexpected failure as a 500 quoting a reference, logged under it
/// — never the failure's own text.
fn refuse(method: &Method, uri: &Uri, error: ScanError) -> Response {
    match error {
        ScanError::Invalid(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        ScanError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
        ScanError::Unexpected(failure) => {
            let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
            tracing::error!(reference = %reference, method = %method, path = uri.path(), error = %failure, "Unexpected failure");
            Problem::handler(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
            )
            .with("correlationId", reference)
            .into_response()
        }
    }
}

/// A `200` with the body Jackson would have written.
fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// The SBOM verbatim, **as an attachment**: megabytes of JSON a browser asked to render inline freezes on.
fn sbom(id: i64, document: String) -> Response {
    let mut response = Response::new(Body::from(document));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"vectispire-scan-{id}.sbom.json\""))
    {
        response.headers_mut().insert(header::CONTENT_DISPOSITION, disposition);
    }
    response
}

fn instant(value: Option<OffsetDateTime>) -> Option<String> {
    value.map(vectispire_cp_audit::iso_instant)
}

/// `ScanSummary`, member for member in the record's order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanSummary {
    id: i64,
    status: String,
    branch: String,
    created_at: Option<String>,
    duration_ms: Option<i64>,
    findings_count: i32,
    new_issues_count: i32,
    resolved_issues_count: i32,
    error: Option<String>,
    claimed_by: Option<String>,
    attempts: i32,
    not_before: Option<String>,
    target_kind: &'static str,
    target_id: Option<i64>,
    target_name: String,
}

impl ScanSummary {
    fn of(scan: &ScanView, names: &Names) -> ScanSummary {
        ScanSummary {
            id: scan.id,
            status: scan.status.clone(),
            branch: scan.branch.clone(),
            created_at: instant(Some(scan.created_at)),
            duration_ms: scan.duration_ms,
            findings_count: scan.findings_count,
            new_issues_count: scan.new_issues_count,
            resolved_issues_count: scan.resolved_issues_count,
            error: scan.error.clone(),
            claimed_by: scan.claimed_by.clone(),
            attempts: scan.attempts,
            not_before: instant(scan.not_before),
            target_kind: if scan.repo_id.is_some() { "repository" } else { "container" },
            target_id: scan.repo_id.or(scan.container_id),
            target_name: names.of(scan.repo_id, scan.container_id),
        }
    }
}

/// `FindingView`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingView {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    severity: Option<String>,
    identifier: Option<String>,
    package_name: Option<String>,
    package_version: Option<String>,
    fix_versions: Option<String>,
    file_path: Option<String>,
    line: Option<i32>,
    description: Option<String>,
    link: Option<String>,
    tool: Option<String>,
    tool_name: Option<String>,
    tool_version: Option<String>,
}

/// `ScanDetail`: the SBOM is not carried — it weighs megabytes and the screen shows none of it; `hasSbom` says whether
/// `/{id}/sbom` has one. `examinedTypes` is `null` when the scan never recorded it, never the empty list, which is
/// "examined nothing".
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanDetail {
    scan: ScanSummary,
    sub_path: Option<String>,
    project_type: Option<String>,
    project_version: Option<String>,
    has_sbom: bool,
    findings: Vec<FindingView>,
    findings_total: i64,
    findings_truncated: bool,
    plugins: Vec<PluginOutcome>,
    examined_types: Option<Vec<&'static str>>,
}

impl ScanDetail {
    fn of(detail: &Detail) -> Result<ScanDetail, ScanError> {
        let scan = &detail.scan;
        Ok(ScanDetail {
            scan: ScanSummary::of(scan, &detail.names),
            sub_path: scan.sub_path.clone(),
            project_type: scan.project_type.clone(),
            project_version: scan.version.clone(),
            has_sbom: scan.has_sbom,
            findings: detail
                .findings
                .iter()
                .map(|finding| FindingView {
                    id: finding.id,
                    kind: finding.kind.clone(),
                    severity: finding.severity.clone(),
                    identifier: finding.identifier.clone(),
                    package_name: finding.package_name.clone(),
                    package_version: finding.package_version.clone(),
                    fix_versions: finding.fix_versions.clone(),
                    file_path: finding.file_path.clone(),
                    line: finding.line,
                    description: finding.description.clone(),
                    link: finding.link.clone(),
                    tool: finding.tool.clone(),
                    tool_name: finding.tool_name.clone(),
                    tool_version: finding.tool_version.clone(),
                })
                .collect(),
            findings_total: detail.findings_total,
            findings_truncated: detail.findings_truncated(),
            plugins: PluginOutcome::read(scan.plugin_steps.as_deref()).map_err(ScanError::unexpected)?,
            examined_types: examined_types::read(scan.examined_types.as_deref()).map(|types| {
                let mut names: Vec<&'static str> = types.into_iter().map(|kind| kind.wire_name()).collect();
                names.sort_unstable();
                names
            }),
        })
    }
}
