//! The tickets' routes:
//!
//! - `GET /api/v1/issues/{issueId}/tickets` (`list`): any account — the issue's own visibility gates its tickets;
//! - `POST /api/v1/issues/{issueId}/tickets` (`create`): a writing account — 201, the issue's visibility first;
//! - `POST /api/v1/tickets/webhook/{provider}` (`handleWebhook`): anonymous — the tracker is the caller, and the
//!   secret is the whole of its authentication. A refusal is a problem document; a delivery read keeps its shape.

mod read;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_access::security::CallerScope;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::extract::{JsonBody, Scoped, UNREADABLE};
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};
use vectispire_domain::tickets::{Presented, TicketProvider};

use crate::error::TicketError;
use crate::links::TicketLinkService;
use crate::webhook::{Outcome, TicketingWebhookService};

const TICKETS: &str = "/api/v1/issues/{issueId}/tickets";
const WEBHOOK: &str = "/api/v1/tickets/webhook/{provider}";

/// How `actionTaken` begins for a delivery ignored because the tracker is disabled: a token a delivery log is searched
/// for, followed by the sentence a person reads.
const IGNORED_INTEGRATION_DISABLED: &str = "ignored_integration_disabled";

macro_rules! read {
    ($attempt:expr) => {
        match $attempt {
            Ok(value) => value,
            Err(problem) => return Problem::into_response(problem),
        }
    };
}

fn ok<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A refusal as `ApiExceptionHandler` answers it; anything else as the unexpected failure it is, with a reference.
fn refusal(method: &str, path: &str, error: TicketError) -> Response {
    match error {
        TicketError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
        TicketError::InvalidInput(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        TicketError::IntegrationDisabled(integration) => {
            Problem::handler(StatusCode::CONFLICT, TicketError::IntegrationDisabled(integration).to_string())
                .caused_by(vectispire_domain::integrations::DISABLED_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        failure @ TicketError::Failed(_) => unexpected(method, path, &failure),
    }
}

fn unexpected(method: &str, path: &str, failure: &dyn std::fmt::Display) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, method, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers.get(header::USER_AGENT).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

/// `WebhookSyncResult`: `issueId` the first issue carrying the reference, `issueIds` every one, oldest first.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookSyncResult {
    matched: bool,
    issue_id: Option<i64>,
    issue_ids: Vec<i64>,
    ticket_ref: Option<String>,
    action_taken: String,
}

impl WebhookSyncResult {
    fn unmatched(ticket_ref: Option<String>, action_taken: String) -> WebhookSyncResult {
        WebhookSyncResult { matched: false, issue_id: None, issue_ids: Vec::new(), ticket_ref, action_taken }
    }
}

/// The module's three routes.
pub fn routes(links: Arc<TicketLinkService>, webhooks: Arc<TicketingWebhookService>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    let list = links.clone();
    entries.push(Route::get(TICKETS).requires(Access::Account).scoped().handler(
        move |Path(raw_id): Path<String>, uri: Uri, Scoped(scope): Scoped<CallerScope>| {
            let links = list.clone();
            async move {
                let issue_id = read!(read::path_long("issueId", &raw_id));
                let limit = read!(read::query_int(uri.query(), "limit")).map(i64::from);
                let offset = read!(read::query_int(uri.query(), "offset")).map(i64::from);
                let Ok(allowance) = scope else {
                    return unexpected("GET", TICKETS, &"the caller's visibility could not be resolved");
                };
                match links.list(issue_id, &allowance.visibility, limit, offset).await {
                    Ok(tickets) => ok(StatusCode::OK, &tickets),
                    Err(refused) => refusal("GET", TICKETS, refused),
                }
            }
        },
    ));

    let create = links;
    entries.push(Route::post(TICKETS).requires(Access::WriteAccount).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Path(raw_id): Path<String>,
              Scoped(scope): Scoped<CallerScope>,
              JsonBody(body): JsonBody<Value>| {
            let links = create.clone();
            async move {
                let issue_id = read!(read::path_long("issueId", &raw_id));
                // Read as Jackson binds the record: a body that is not an object, or a field of the wrong shape, is
                // the one 400 sentence; a field absent is handed on as absent.
                let fields = read!(read::object(&body));
                let provider = read!(read::text(fields.get("provider")));
                let key = read!(read::text(fields.get("ticketKey")));
                let url = read!(read::text(fields.get("ticketUrl")));
                let Ok(allowance) = scope else {
                    return unexpected("POST", TICKETS, &"the caller's visibility could not be resolved");
                };
                let actor = RequestActor {
                    username: Some(vectispire_cp_access::security::actor_name(&caller.0, "unknown")),
                    ip_address: Some(address.0.clone()),
                    user_agent: user_agent(&headers),
                };
                match links
                    .attach(issue_id, &allowance.visibility, provider.as_deref(), key.as_deref(), url.as_deref(), actor)
                    .await
                {
                    Ok(view) => ok(StatusCode::CREATED, &view),
                    Err(refused) => refusal("POST", TICKETS, refused),
                }
            }
        },
    ));

    entries.push(Route::post(WEBHOOK).requires(Access::Anonymous).names_no_target().handler(
        move |Path(provider): Path<String>, address: ClientAddress, headers: HeaderMap, body: Body| {
            let webhooks = webhooks.clone();
            async move {
                let body = read!(read::raw_body(body).await);
                // `@RequestBody String`: required, so an empty body is the unreadable request, before the controller.
                if body.is_empty() {
                    return Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE).into_response();
                }
                let Some(parsed) = TicketProvider::from_wire_name(Some(&provider)) else {
                    return Problem::handler(StatusCode::BAD_REQUEST, format!("Unsupported provider: {provider}"))
                        .into_response();
                };
                let raw = String::from_utf8_lossy(&body).into_owned();
                let presented = Presented {
                    gitlab_token: header_value(&headers, "x-gitlab-token"),
                    github_signature: header_value(&headers, "x-hub-signature-256"),
                    shared_token: header_value(&headers, "x-vectispire-token"),
                };
                // `RequestActors.unnamed`: the caller's address and agent, no name.
                let origin = RequestActor {
                    username: None,
                    ip_address: Some(address.0.clone()),
                    user_agent: user_agent(&headers),
                };
                let outcome = match webhooks.handle(parsed, &raw, &presented, &origin).await {
                    Ok(outcome) => outcome,
                    Err(failed) => return refusal("POST", WEBHOOK, failed),
                };
                match outcome {
                    // No detail: a caller learning *which* header was wrong learns which tracker we expect.
                    Outcome::Rejected => {
                        Problem::handler(StatusCode::UNAUTHORIZED, "Webhook authentication failed").into_response()
                    }
                    // Said plainly: it lands in the tracker's delivery log.
                    Outcome::NotConfigured => Problem::handler(
                        StatusCode::FORBIDDEN,
                        "The ticket webhook is not configured on this instance: an administrator has to set its secret \
                         first",
                    )
                    .into_response(),
                    Outcome::Malformed => {
                        Problem::handler(StatusCode::BAD_REQUEST, "Malformed JSON body").into_response()
                    }
                    // 200: the tracker's own redelivery lands here too, and an error would make it retry.
                    Outcome::AlreadyProcessed => {
                        ok(StatusCode::OK, &WebhookSyncResult::unmatched(None, "Delivery already processed".to_owned()))
                    }
                    // 200, not 409: GitLab disables a webhook after repeated failures.
                    Outcome::IgnoredIntegrationDisabled(integration) => {
                        let key = integration.key();
                        ok(
                            StatusCode::OK,
                            &WebhookSyncResult::unmatched(
                                None,
                                format!(
                                    "{IGNORED_INTEGRATION_DISABLED}: the {key} integration is disabled on this \
                                     installation and nothing was applied; a platform governor enables it with PUT \
                                     /api/v1/integrations/{key}/enabled"
                                ),
                            ),
                        )
                    }
                    Outcome::NoReference => ok(
                        StatusCode::OK,
                        &WebhookSyncResult::unmatched(None, "No ticket reference extracted from payload".to_owned()),
                    ),
                    Outcome::NoMatchingIssue(ticket_ref) => ok(
                        StatusCode::OK,
                        &WebhookSyncResult::unmatched(
                            Some(ticket_ref),
                            "No matching Vectispire issue found".to_owned(),
                        ),
                    ),
                    Outcome::Synced { issue_ids, ticket_ref, action_taken } => ok(
                        StatusCode::OK,
                        &WebhookSyncResult {
                            matched: true,
                            issue_id: issue_ids.first().copied(),
                            issue_ids,
                            ticket_ref: Some(ticket_ref),
                            action_taken,
                        },
                    ),
                }
            }
        },
    ));

    entries
}
