//! What the channels share and nobody outside reads.

use time::OffsetDateTime;
use vectispire_cp_outbound::{OutboundPolicy, PostError};
use vectispire_cp_outbox::DeliveryError;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::instant::Instant;

/// A read of the database that failed during a delivery: Java's data-access exception, which the relay retries.
pub(crate) fn data_access(error: impl std::fmt::Display) -> DeliveryError {
    DeliveryError::failed("DataAccessException", error.to_string())
}

/// A send that failed: the exception Java's door throws, under its own name.
pub(crate) fn post_failure(error: &PostError) -> DeliveryError {
    DeliveryError::failed(error.kind(), error.to_string())
}

/// `notification_allow_private_url`: one rule for every notification channel — a URL resolving to a private address
/// is far more often a server-side request forgery attempt than an intranet endpoint.
pub(crate) async fn policy(settings: &Settings) -> Result<OutboundPolicy, DeliveryError> {
    Ok(if settings.is_enabled(Setting::NotificationAllowPrivateUrl).await.map_err(data_access)? {
        OutboundPolicy::InternalAllowed
    } else {
        OutboundPolicy::PublicOnly
    })
}

/// A stored setting, `trim`med.
pub(crate) async fn trimmed(
    settings: &Settings,
    setting: Setting,
) -> Result<String, vectispire_cp_settings::SettingsError> {
    Ok(vectispire_domain::java::trim(&settings.get(setting).await?).to_owned())
}

pub(crate) fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

/// A stored payload that does not read: Jackson's exception in Java, retried then abandoned.
pub(crate) fn unreadable(error: &serde_json::Error) -> DeliveryError {
    DeliveryError::failed("JsonProcessingException", error.to_string())
}
