//! The platform module's routes, as far as their services are ported: `AuditLogController` over `cp-audit`'s
//! [`AuditLogQuery`], `CryptoController` over `cp-crypto`'s [`SigningKeys`]. `SettingsController` follows with the
//! modules it composes (`README.md` says which).

use std::sync::Arc;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_audit::AuditLogQuery;
use vectispire_cp_crypto::SigningKeys;
use vectispire_cp_http::Problem;
use vectispire_cp_http::routes::RouteEntry;

mod audit_log;
mod crypto;
mod read;

/// The six routes: the audit trail's three, and the signing key's three.
pub fn routes(trail: Arc<AuditLogQuery>, signing: Arc<SigningKeys>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    audit_log::routes(trail, &mut entries);
    crypto::routes(signing, &mut entries);
    entries
}

fn ok<T: Serialize + ?Sized>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// `InvalidInputException`: a 400 in the service's words.
fn bad_request(message: String) -> Response {
    Problem::handler(StatusCode::BAD_REQUEST, message).into_response()
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(method: &str, path: &str, failure: &dyn std::error::Error) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, method, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}
