//! The notification centre's routes — `NotificationCenterController`:
//!
//! - `GET /api/v1/notifications/channels` (`getChannels`): any account — each channel switched on, its destination
//!   masked, whether it is configured;
//! - `POST /api/v1/notifications/test/{channelType}` (`testChannel`): security lead — it posts to somebody else's Slack
//!   or Teams, so it belongs to whoever configured the channel.
//!
//! Neither names a target.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_http::Problem;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};

use crate::error::NotificationError;
use crate::service::NotificationTestService;

const CHANNELS: &str = "/api/v1/notifications/channels";
const TEST: &str = "/api/v1/notifications/test/{channelType}";

fn ok<T: Serialize>(value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A refusal as `ApiExceptionHandler` answers it; anything else as the unexpected failure it is, with a reference.
fn refuse(method: &str, path: &str, error: NotificationError) -> Response {
    match error {
        NotificationError::IntegrationDisabled(integration) => {
            Problem::handler(StatusCode::CONFLICT, NotificationError::IntegrationDisabled(integration).to_string())
                .caused_by(vectispire_domain::integrations::DISABLED_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        failure @ NotificationError::Failed(_) => {
            let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
            tracing::error!(reference = %reference, method, path, error = %failure, "Unexpected failure");
            Problem::handler(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
            )
            .with("correlationId", reference)
            .into_response()
        }
    }
}

/// The module's two routes.
pub fn routes(service: Arc<NotificationTestService>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    let list = service.clone();
    entries.push(Route::get(CHANNELS).requires(Access::Account).names_no_target().handler(move || {
        let service = list.clone();
        async move {
            match service.channels_status().await {
                Ok(channels) => ok(&channels),
                Err(failure) => refuse("GET", CHANNELS, failure),
            }
        }
    }));

    let test = service;
    entries.push(Route::post(TEST).requires(Access::SecurityLead).names_no_target().handler(
        move |Path(channel_type): Path<String>| {
            let service = test.clone();
            async move {
                match service.test_channel(&channel_type).await {
                    Ok(result) => ok(&result),
                    Err(failure) => refuse("POST", TEST, failure),
                }
            }
        },
    ));

    entries
}
