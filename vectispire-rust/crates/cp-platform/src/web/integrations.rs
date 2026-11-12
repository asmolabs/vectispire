//! The integrations' registry (decision 0040) — `IntegrationsController`: read by every account, switched by the
//! platform governor.
//!
//! - `GET /api/v1/integrations` (`listIntegrations`): any account — every integration with whether it is enabled;
//!   `updatedBy` only for a reader of governance;
//! - `PUT /api/v1/integrations/{key}/enabled` (`setIntegrationEnabled`): the platform governor — 404 for a key no
//!   integration has, 400 without `enabled`, 409 `integration-in-use` for what a configuration uses.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::extract::UNREADABLE;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};
use vectispire_cp_settings::{IntegrationView, IntegrationsError};
use vectispire_domain::integrations::IN_USE_CAUSE;

use super::{bad_request, ok, unexpected};
use crate::integrations::{IntegrationAdministration, IntegrationAdministrationError};

pub(super) const LIST: &str = "/api/v1/integrations";
pub(super) const ENABLED: &str = "/api/v1/integrations/{key}/enabled";

/// `IntegrationView` as Jackson writes the record: every member, `null` included.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IntegrationResponse {
    key: String,
    family: &'static str,
    name: &'static str,
    enabled: bool,
    /// `Instant.toString`; `null` while no governor has switched it.
    updated_at: Option<String>,
    updated_by: Option<String>,
}

impl IntegrationResponse {
    fn of(view: IntegrationView) -> IntegrationResponse {
        IntegrationResponse {
            key: view.key,
            family: view.family,
            name: view.name,
            enabled: view.enabled,
            updated_at: view.updated_at.map(vectispire_cp_audit::iso_instant),
            updated_by: view.updated_by,
        }
    }
}

/// `IntegrationEnabled(Boolean enabled)`, the body optional (`@RequestBody(required = false)`): absent, `null` or
/// without the member is no state, refused by the service in its words; a member Jackson cannot read as a `Boolean`
/// refuses the body.
fn enabled_of(body: &[u8]) -> Result<Option<bool>, Problem> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let unreadable = || Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE);
    match serde_json::from_slice::<Value>(body).map_err(|_| unreadable())? {
        Value::Null => Ok(None),
        Value::Object(fields) => match fields.get("enabled") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(enabled)) => Ok(Some(*enabled)),
            // Jackson's scalar coercion: the texts of a boolean read as one.
            Some(Value::String(text)) if text == "true" => Ok(Some(true)),
            Some(Value::String(text)) if text == "false" => Ok(Some(false)),
            Some(_) => Err(unreadable()),
        },
        _ => Err(unreadable()),
    }
}

/// `ApiExceptionHandler` on what the service throws.
fn refuse(method: &str, path: &str, error: IntegrationAdministrationError) -> Response {
    match error {
        IntegrationAdministrationError::NotFound => {
            Problem::handler(StatusCode::NOT_FOUND, IntegrationAdministrationError::NotFound.to_string())
                .into_response()
        }
        IntegrationAdministrationError::NoState => bad_request(IntegrationAdministrationError::NoState.to_string()),
        IntegrationAdministrationError::Registry(IntegrationsError::InUse(integration, using)) => {
            Problem::handler(StatusCode::CONFLICT, IntegrationsError::InUse(integration, using).to_string())
                .caused_by(IN_USE_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        IntegrationAdministrationError::Registry(failure) => unexpected(method, path, &failure),
    }
}

fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

pub(super) fn routes(service: Arc<IntegrationAdministration>, entries: &mut Vec<RouteEntry>) {
    let listing = service.clone();
    entries.push(Route::get(LIST).requires(Access::Account).names_no_target().handler(move |caller: Caller| {
        let service = listing.clone();
        async move {
            // `Role.hasGlobalSecurityScope`: the roles that read governance.
            let reads_governance = Access::GovernanceRead.admits(caller.0.role());
            match service.list(reads_governance).await {
                Ok(all) => ok(&all.into_iter().map(IntegrationResponse::of).collect::<Vec<_>>()),
                Err(failure) => unexpected("GET", LIST, &failure),
            }
        }
    }));

    entries.push(Route::put(ENABLED).requires(Access::PlatformGovernor).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(key): Path<String>, body: Bytes| {
            let service = service.clone();
            async move {
                let enabled = match enabled_of(&body) {
                    Ok(enabled) => enabled,
                    Err(refused) => return refused.into_response(),
                };
                let governor = caller.0.account.as_ref().map(|account| account.username.clone()).unwrap_or_default();
                match service.set_enabled(&key, enabled, &governor, &actor(&caller, &address, &headers)).await {
                    Ok(view) => ok(&IntegrationResponse::of(view)),
                    Err(refused) => refuse("PUT", ENABLED, refused),
                }
            }
        },
    ));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_state_is_read_as_jackson_reads_the_record() {
        assert_eq!(enabled_of(b"").unwrap(), None, "no body is no state");
        assert_eq!(enabled_of(b"{}").unwrap(), None);
        assert_eq!(enabled_of(b"null").unwrap(), None);
        assert_eq!(enabled_of(br#"{"enabled":null}"#).unwrap(), None, "null is refused by the service, never off");
        assert_eq!(enabled_of(br#"{"enabled":false,"other":1}"#).unwrap(), Some(false));
        assert_eq!(enabled_of(br#"{"enabled":"true"}"#).unwrap(), Some(true));
        assert_eq!(enabled_of(br#"{"enabled":[true]}"#).unwrap_err().detail(), UNREADABLE);
        assert_eq!(enabled_of(b"[]").unwrap_err().detail(), UNREADABLE);
        assert_eq!(enabled_of(b"not json").unwrap_err().detail(), UNREADABLE);
    }

    #[test]
    fn a_refusal_is_answered_in_java_s_statuses() {
        let status = |error| refuse("PUT", ENABLED, error).status();
        assert_eq!(status(IntegrationAdministrationError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(status(IntegrationAdministrationError::NoState), StatusCode::BAD_REQUEST);
        let tls = vectispire_domain::integrations::Integration::by_key("siem.syslog_tls").unwrap();
        assert_eq!(
            status(IntegrationAdministrationError::Registry(IntegrationsError::InUse(tls, "used.".into()))),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status(IntegrationAdministrationError::Registry(IntegrationsError::Owner("x".into()))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
