//! `AiAdvisorController`:
//!
//! - `GET /api/v1/ai-advisor/status` — any account's: whether the advisor works and which model answers, **never
//!   where it lives** — the Ollama address was published here once, a host and a port on the control plane's network
//!   handed to a caller who may have been given nothing else.
//! - `POST /api/v1/ai-advisor/explain/issue/{issueId}` and `…/explain/cve/{cveId}` — a writing account's, within its
//!   visibility; `language` names the reader's. The CVE route's old `packageName`, `currentVersion`, `fixVersion` and
//!   `reachability` are not read: the caller's word was printed as the advice's facts.
//!
//! None takes an API key: the controller is not marked `@AcceptsApiKey`.

mod read;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, Uri, header};
use serde::Serialize;
use vectispire_cp_access::security::CallerScope;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Problem, Scoped};
use vectispire_domain::integrations::DISABLED_CAUSE;

use crate::advisor::{AdvisorError, AiAdvisorService};
use crate::review::{AiReviewService, ReviewError};

/// The services a route reaches.
#[derive(Debug, Clone)]
pub struct Services {
    pub reviews: AiReviewService,
    pub advisor: AiAdvisorService,
}

fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(path: &str, failure: &str) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}

fn refuse(path: &str, error: AdvisorError) -> Response {
    match error {
        AdvisorError::InvalidInput(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        AdvisorError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
        AdvisorError::Review(disabled @ ReviewError::Disabled(integration)) => {
            Problem::handler(StatusCode::CONFLICT, disabled.to_string())
                .caused_by(DISABLED_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        AdvisorError::Review(ReviewError::Failed(failure)) => unexpected(path, &failure),
    }
}

/// `{enabled, availableModels, selectedModel, providerEnabled}`, in the order the recording carries.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    enabled: bool,
    available_models: Vec<String>,
    selected_model: String,
    provider_enabled: bool,
}

async fn status(reviews: &AiReviewService) -> Result<Status, ReviewError> {
    Ok(Status {
        enabled: reviews.is_enabled().await?,
        available_models: reviews.available_models().await?,
        selected_model: reviews.selected_model().await?,
        provider_enabled: reviews.provider_enabled().await?,
    })
}

const ISSUE: &str = "/api/v1/ai-advisor/explain/issue/{issueId}";
const CVE: &str = "/api/v1/ai-advisor/explain/cve/{cveId}";

/// Every route of the module.
pub fn routes(services: Arc<Services>) -> Vec<RouteEntry> {
    let (on_status, on_issue, on_cve) = (services.clone(), services.clone(), services);
    vec![
        Route::get("/api/v1/ai-advisor/status").requires(Access::Account).names_no_target().handler(move || {
            let s = on_status.clone();
            async move {
                match status(&s.reviews).await {
                    Ok(status) => ok(&status),
                    Err(failure) => unexpected("/api/v1/ai-advisor/status", &failure.to_string()),
                }
            }
        }),
        Route::post(ISSUE).requires(Access::WriteAccount).scoped().handler(
            move |uri: Uri, Path(raw): Path<String>, Scoped(scope): Scoped<CallerScope>| {
                let s = on_issue.clone();
                async move {
                    let Ok(allowed) = scope else {
                        return unexpected(ISSUE, "the caller's visibility could not be resolved");
                    };
                    let issue_id = match read::path_long("issueId", &raw) {
                        Ok(id) => id,
                        Err(problem) => return problem.into_response(),
                    };
                    let language = read::query_string(uri.query(), "language");
                    match s.advisor.explain_issue(issue_id, language.as_deref(), &allowed.visibility).await {
                        Ok(advice) => ok(&advice),
                        Err(error) => refuse(ISSUE, error),
                    }
                }
            },
        ),
        Route::post(CVE).requires(Access::WriteAccount).scoped().handler(
            move |uri: Uri, Path(cve_id): Path<String>, Scoped(scope): Scoped<CallerScope>| {
                let s = on_cve.clone();
                async move {
                    let Ok(allowed) = scope else {
                        return unexpected(CVE, "the caller's visibility could not be resolved");
                    };
                    let language = read::query_string(uri.query(), "language");
                    match s.advisor.explain_cve(&cve_id, language.as_deref(), &allowed.visibility).await {
                        Ok(advice) => ok(&advice),
                        Err(error) => refuse(CVE, error),
                    }
                }
            },
        ),
    ]
}
