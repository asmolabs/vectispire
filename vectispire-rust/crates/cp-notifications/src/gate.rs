//! `ChannelGate`: what every channel asks the integrations' registry before it sends (decision 0040, lot I6) — the
//! one place the answer becomes a hold, a refusal or a skip.
//!
//! **Asked at the channel's entry, not by the relay**: the relay is one caller among five — the weekly report, the
//! checklist reminders, the token alerts and the test button reach a channel without it — and a gate in front of
//! one caller is a gate the next goes round.

use vectispire_cp_outbox::DeliveryError;
use vectispire_cp_settings::Integrations;
use vectispire_domain::notifications::NotificationChannelKind;

use crate::error::NotificationError;
use crate::internal::data_access;

/// Whether the channel's integration is on.
pub async fn is_on(registry: &Integrations, kind: NotificationChannelKind) -> Result<bool, NotificationError> {
    Ok(registry.is_enabled(kind.integration()).await?)
}

/// What a delivery from the outbox asks first. **Held, never failed nor abandoned**: a row for a disabled channel
/// exists only when something went round the in-use refusal, and counted as a failure it would be abandoned in four
/// hours — an alert lost to a switch a governor may turn back in a minute.
pub async fn require_deliverable(registry: &Integrations, kind: NotificationChannelKind) -> Result<(), DeliveryError> {
    match registry.is_enabled(kind.integration()).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(DeliveryError::Held(format!(
            "the notification channel \"{}\" is disabled on this installation: the message waits until the platform \
             governor enables it",
            kind.integration().key()
        ))),
        Err(unread) => Err(data_access(unread)),
    }
}

/// What a send outside the outbox asks first — the weekly report, a reminder, the test button: nothing waits for
/// those, so the refusal is the integration's own, 409 `integration-disabled`.
pub async fn require_enabled(registry: &Integrations, kind: NotificationChannelKind) -> Result<(), NotificationError> {
    if is_on(registry, kind).await? { Ok(()) } else { Err(NotificationError::IntegrationDisabled(kind.integration())) }
}
