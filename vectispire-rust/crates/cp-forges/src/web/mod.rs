//! Forges' routes — `ForgeConnectionsController`, `ForgeDiscoveriesController`, `ForgeImportsController`.
//! **Administrators only**: a connection reveals the name of every repository an organisation holds, and a discovery
//! lists repositories no grant covers yet. None names a target. The services probe, decide and audit; these map the
//! requests, and the token never comes back out.

mod discoveries;
pub(crate) mod read;

use std::sync::Arc;

use axum::body::Body;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};

use crate::Services;
use crate::connections::{Change, Creation};
use crate::error::ForgeError;

const CONNECTIONS: &str = "/api/v1/forge-connections";
const CONNECTION: &str = "/api/v1/forge-connections/{id}";
const TOKEN: &str = "/api/v1/forge-connections/{id}/token";
pub(crate) const DISCOVERIES: &str = "/api/v1/forge-connections/{connectionId}/discoveries";
pub(crate) const DISCOVERY: &str = "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}";
pub(crate) const REPOSITORIES: &str = "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}/repositories";
pub(crate) const SELECTION: &str = "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}/selection";
pub(crate) const IMPORTS: &str = "/api/v1/forge-connections/{connectionId}/imports";
pub(crate) const PREVIEW: &str = "/api/v1/forge-connections/{connectionId}/imports/preview";

pub(crate) fn json_response<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

pub(crate) fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    json_response(StatusCode::OK, value)
}

/// `ApiExceptionHandler` on what the services throw.
pub(crate) fn refuse(method: &str, path: &str, error: ForgeError) -> Response {
    match error {
        ForgeError::InvalidInput(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        ForgeError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
        ForgeError::Disabled(integration) => {
            Problem::handler(StatusCode::CONFLICT, ForgeError::Disabled(integration).to_string())
                .caused_by(vectispire_domain::integrations::DISABLED_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        ForgeError::Conflict { cause, message, members } => {
            let mut problem = Problem::handler(StatusCode::CONFLICT, message).caused_by(cause);
            for (name, value) in members {
                problem = problem.with(name, value);
            }
            problem.into_response()
        }
        ForgeError::Unexpected(failure) => unexpected(method, path, &failure),
    }
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(method: &str, path: &str, failure: &str) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, method, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}

/// `RequestActors.of(principal, request)`.
pub(crate) fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

pub(crate) fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok())
}

macro_rules! or_answer {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(problem) => return problem.into_response(),
        }
    };
}

/// An optional body read as a record: `None` when absent or `null`, its fields otherwise.
pub(crate) fn optional_record(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<serde_json::Map<String, Value>>, Problem> {
    match read::optional_json(content_type(headers), body)? {
        None => Ok(None),
        Some(Value::Object(fields)) => Ok(Some(fields)),
        Some(_) => Err(Problem::handler(StatusCode::BAD_REQUEST, read::UNREADABLE)),
    }
}

fn creation(fields: &serde_json::Map<String, Value>) -> Result<Creation, Problem> {
    Ok(Creation {
        name: read::text(fields.get("name"))?,
        kind: read::text(fields.get("kind"))?,
        base_url: read::text(fields.get("baseUrl"))?,
        owner: read::text(fields.get("owner"))?,
        internal_network: read::flag(fields.get("internalNetwork"))?,
        ca_pem: read::text(fields.get("caPem"))?,
        token: read::text(fields.get("token"))?,
    })
}

fn change(fields: &serde_json::Map<String, Value>) -> Result<Change, Problem> {
    Ok(Change {
        name: read::text(fields.get("name"))?,
        internal_network: read::flag(fields.get("internalNetwork"))?,
        ca_pem: read::text(fields.get("caPem"))?,
    })
}

/// The module's routes.
pub(crate) fn routes(services: Arc<Services>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    let s = services.clone();
    entries.push(Route::get(CONNECTIONS).requires(Access::Administrator).names_no_target().handler(
        move |RawQuery(query): RawQuery| {
            let s = s.clone();
            async move {
                let limit = or_answer!(read::query_int(query.as_deref(), "limit"));
                let offset = or_answer!(read::query_int(query.as_deref(), "offset"));
                match s.connections.list(limit.map(i64::from), offset.map(i64::from)).await {
                    Ok(views) => ok(&views),
                    Err(refused) => refuse("GET", CONNECTIONS, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::get(CONNECTION).requires(Access::Administrator).names_no_target().handler(
        move |Path(id): Path<String>| {
            let s = s.clone();
            async move {
                let id = or_answer!(read::path_uuid("id", &id));
                match s.connections.get(&id).await {
                    Ok(view) => ok(&view),
                    Err(refused) => refuse("GET", CONNECTION, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::post(CONNECTIONS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, body: Bytes| {
            let s = s.clone();
            async move {
                let fields = or_answer!(optional_record(&headers, &body));
                let request = or_answer!(fields.as_ref().map(creation).transpose());
                match s.connections.create(request, &actor(&caller, &address, &headers)).await {
                    Ok(view) => json_response(StatusCode::CREATED, &view),
                    Err(refused) => refuse("POST", CONNECTIONS, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::put(TOKEN).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, body: Bytes| {
            let s = s.clone();
            async move {
                let id = or_answer!(read::path_uuid("id", &id));
                let fields = or_answer!(optional_record(&headers, &body));
                let token = match &fields {
                    None => None,
                    Some(fields) => or_answer!(read::text(fields.get("token"))),
                };
                match s.connections.replace_token(&id, token.as_deref(), &actor(&caller, &address, &headers)).await {
                    Ok(view) => ok(&view),
                    Err(refused) => refuse("PUT", TOKEN, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::patch(CONNECTION).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, body: Bytes| {
            let s = s.clone();
            async move {
                let id = or_answer!(read::path_uuid("id", &id));
                let fields = or_answer!(optional_record(&headers, &body));
                let requested = or_answer!(fields.as_ref().map(change).transpose());
                match s.connections.update(&id, requested, &actor(&caller, &address, &headers)).await {
                    Ok(view) => ok(&view),
                    Err(refused) => refuse("PATCH", CONNECTION, refused),
                }
            }
        },
    ));

    discoveries::routes(&services, &mut entries);

    let s = services;
    entries.push(Route::delete(CONNECTION).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
            let s = s.clone();
            async move {
                let id = or_answer!(read::path_uuid("id", &id));
                match s.connections.delete(&id, &actor(&caller, &address, &headers)).await {
                    Ok(()) => StatusCode::NO_CONTENT.into_response(),
                    Err(refused) => refuse("DELETE", CONNECTION, refused),
                }
            }
        },
    ));

    entries
}
