//! Why a notification gesture was refused or failed.

use vectispire_domain::integrations::Integration;

#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    /// `IntegrationDisabledException`: a send outside the outbox to a channel the governor switched off — 409.
    #[error("{}", .0.disabled_message(""))]
    IntegrationDisabled(Integration),
    /// The settings, the registry or the teams could not be read: a failure, never "not configured".
    #[error("{0}")]
    Failed(String),
}

impl From<vectispire_cp_settings::SettingsError> for NotificationError {
    fn from(error: vectispire_cp_settings::SettingsError) -> NotificationError {
        NotificationError::Failed(error.to_string())
    }
}

impl From<vectispire_cp_settings::IntegrationsError> for NotificationError {
    fn from(error: vectispire_cp_settings::IntegrationsError) -> NotificationError {
        match error {
            vectispire_cp_settings::IntegrationsError::Disabled(integration) => {
                NotificationError::IntegrationDisabled(integration)
            }
            other => NotificationError::Failed(other.to_string()),
        }
    }
}
