//! The SIEM export's routes — `SiemController`:
//!
//! - `GET /api/v1/siem/config` (`getConfig`): governance read — the stored configuration, or the default a screen
//!   shows before the first save (off, webhook, `HIGH`);
//! - `PUT /api/v1/siem/config` (`updateConfig`): security lead — saved, audited, the collector being left told;
//! - `POST /api/v1/siem/test` (`testConnection`): security lead — one health-check event, an outcome in return.
//!
//! None names a target: the configuration is the deployment's, a singleton.

use std::sync::Arc;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_crypto::EncryptionError;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, JsonBody, Problem};
use vectispire_domain::secret::Secret;

use crate::config::{SiemConfigUpdate, SiemConfigView, SiemExporterService, TestResult};
use crate::error::SiemError;

/// `SiemConfigRequest`. `enabled` is a primitive `boolean` on the Java side: absent or `null` is `false`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigRequest {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    auth_header: Option<String>,
    #[serde(default)]
    min_severity: Option<String>,
    #[serde(default)]
    tls_ca_pem: Option<String>,
}

/// `SiemTestRequest`: `protocol` absent tests the stored one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestRequest {
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    auth_header: Option<String>,
    #[serde(default)]
    tls_ca_pem: Option<String>,
}

/// `SiemConfigResponse`: never the header, only whether one is set. Every member is written, `null` included, as
/// Jackson writes a record.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ConfigResponse {
    enabled: bool,
    protocol: String,
    endpoint: Option<String>,
    has_auth_header: bool,
    min_severity: String,
    tls_ca_pem: Option<String>,
    tls_ca_subject: Option<String>,
    /// `Instant.toString`.
    tls_ca_not_after: Option<String>,
    /// `Instant.toString`.
    updated_at: Option<String>,
}

impl ConfigResponse {
    /// What `getConfig` answers before the first save — `SiemController`'s literal, not a row.
    fn unconfigured() -> ConfigResponse {
        ConfigResponse {
            enabled: false,
            protocol: "WEBHOOK".to_owned(),
            endpoint: None,
            has_auth_header: false,
            min_severity: "HIGH".to_owned(),
            tls_ca_pem: None,
            tls_ca_subject: None,
            tls_ca_not_after: None,
            updated_at: None,
        }
    }

    fn of(view: SiemConfigView) -> ConfigResponse {
        ConfigResponse {
            enabled: view.enabled,
            protocol: view.protocol,
            endpoint: view.endpoint,
            has_auth_header: view.has_auth_header,
            min_severity: view.min_severity,
            tls_ca_pem: view.tls_ca_pem,
            tls_ca_subject: view.tls_ca_subject,
            tls_ca_not_after: view.tls_ca_not_after.and_then(|at| at.to_java_string()),
            updated_at: Some(vectispire_cp_audit::iso_instant(view.updated_at)),
        }
    }
}

/// `SiemExporterService.TestResult`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestResponse {
    success: bool,
    message: String,
    status_code: i32,
}

impl From<TestResult> for TestResponse {
    fn from(result: TestResult) -> TestResponse {
        TestResponse { success: result.success, message: result.message, status_code: result.status_code }
    }
}

fn ok<T: Serialize>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A refusal as `ApiExceptionHandler` answers it; anything else as the unexpected failure it is, with a reference —
/// never the failure's own text.
fn refuse(method: &str, path: &str, error: SiemError) -> Response {
    match error {
        SiemError::InvalidInput(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        // `MissingEncryptionKeyException`: a header cannot be stored without a key, and in the clear is never right.
        SiemError::Encryption(EncryptionError::MissingKey) => {
            Problem::handler(StatusCode::PRECONDITION_FAILED, EncryptionError::MissingKey.to_string()).into_response()
        }
        // `UnsafeUrlException`: the guard refused the KMS's address.
        SiemError::Encryption(EncryptionError::UnsafeUrl(message)) => {
            Problem::handler(StatusCode::UNPROCESSABLE_ENTITY, message).into_response()
        }
        failure @ (SiemError::Encryption(EncryptionError::Kms(_)) | SiemError::Database(_)) => {
            unexpected(method, path, &failure)
        }
    }
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(method: &str, path: &str, failure: &SiemError) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, method, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}

/// `RequestActors.of(principal, request, "system")`.
fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: Some(vectispire_cp_access::security::actor_name(&caller.0, "system")),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

const CONFIG: &str = "/api/v1/siem/config";
const TEST: &str = "/api/v1/siem/test";

/// The module's three routes.
pub fn routes(service: Arc<SiemExporterService>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    let read = service.clone();
    entries.push(Route::get(CONFIG).requires(Access::GovernanceRead).names_no_target().handler(move || {
        let service = read.clone();
        async move {
            match service.get_config().await {
                Ok(Some(view)) => ok(&ConfigResponse::of(view)),
                Ok(None) => ok(&ConfigResponse::unconfigured()),
                Err(failure) => refuse("GET", CONFIG, failure),
            }
        }
    }));

    let save = service.clone();
    entries.push(Route::put(CONFIG).requires(Access::SecurityLead).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, JsonBody(body): JsonBody<ConfigRequest>| {
            let service = save.clone();
            async move {
                let update = SiemConfigUpdate {
                    enabled: body.enabled.unwrap_or(false),
                    protocol: body.protocol,
                    endpoint: body.endpoint,
                    auth_header: body.auth_header.map(Secret::new),
                    min_severity: body.min_severity,
                    tls_ca_pem: body.tls_ca_pem,
                };
                match service.save_config(update, &actor(&caller, &address, &headers)).await {
                    Ok(saved) => ok(&ConfigResponse::of(saved)),
                    Err(failure) => refuse("PUT", CONFIG, failure),
                }
            }
        },
    ));

    let test = service;
    entries.push(Route::post(TEST).requires(Access::SecurityLead).names_no_target().handler(
        move |JsonBody(body): JsonBody<TestRequest>| {
            let service = test.clone();
            async move {
                let header = body.auth_header.map(Secret::new);
                let tested = service
                    .test_connection(
                        body.protocol.as_deref(),
                        body.endpoint.as_deref(),
                        header.as_ref(),
                        body.tls_ca_pem.as_deref(),
                    )
                    .await;
                match tested {
                    Ok(result) => ok(&TestResponse::from(result)),
                    Err(failure) => refuse("POST", TEST, failure),
                }
            }
        },
    ));

    entries
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_unconfigured_answer_is_the_controllers_literal_with_every_member_written() {
        assert_eq!(
            vectispire_domain::wire::to_wire_string(&ConfigResponse::unconfigured()),
            r#"{"enabled":false,"protocol":"WEBHOOK","endpoint":null,"hasAuthHeader":false,"minSeverity":"HIGH","tlsCaPem":null,"tlsCaSubject":null,"tlsCaNotAfter":null,"updatedAt":null}"#
        );
    }

    #[test]
    fn an_absent_or_null_enabled_reads_as_false_as_a_primitive_does() {
        let absent: ConfigRequest = serde_json::from_str(r#"{"endpoint":"x"}"#).unwrap();
        assert_eq!(absent.enabled, None);
        let null: ConfigRequest = serde_json::from_str(r#"{"enabled":null}"#).unwrap();
        assert_eq!(null.enabled, None);
    }

    #[test]
    fn a_refusal_is_400_a_missing_key_412_and_the_rest_a_referenced_500() {
        let status = |error| refuse("PUT", CONFIG, error).status();
        assert_eq!(status(SiemError::InvalidInput("no".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status(SiemError::Encryption(EncryptionError::MissingKey)), StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            status(SiemError::Encryption(EncryptionError::UnsafeUrl("x".into()))),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(status(SiemError::Encryption(EncryptionError::Kms("x".into()))), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status(SiemError::Database("x".into())), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
