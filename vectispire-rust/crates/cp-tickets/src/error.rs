//! Why a ticket gesture was refused or failed.

use vectispire_domain::integrations::Integration;

#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    /// 404, absent and hidden alike: "Issue not found.".
    #[error("{0}")]
    NotFound(String),
    /// `InvalidInputException`: 400 with the sentence.
    #[error("{0}")]
    InvalidInput(String),
    /// `IntegrationDisabledException`: 409 `integration-disabled`, naming the tracker.
    #[error("{}", .0.disabled_message(""))]
    IntegrationDisabled(Integration),
    /// A database or a collaborator that could not be read: never an answer of its own.
    #[error("{0}")]
    Failed(String),
}

impl TicketError {
    pub(crate) fn failed(error: impl std::fmt::Display) -> TicketError {
        TicketError::Failed(error.to_string())
    }
}

impl From<vectispire_cp_settings::SettingsError> for TicketError {
    fn from(error: vectispire_cp_settings::SettingsError) -> TicketError {
        TicketError::Failed(error.to_string())
    }
}

impl From<vectispire_cp_settings::IntegrationsError> for TicketError {
    fn from(error: vectispire_cp_settings::IntegrationsError) -> TicketError {
        match error {
            vectispire_cp_settings::IntegrationsError::Disabled(integration) => {
                TicketError::IntegrationDisabled(integration)
            }
            other => TicketError::Failed(other.to_string()),
        }
    }
}

impl From<crate::persistence::DbError> for TicketError {
    fn from(error: crate::persistence::DbError) -> TicketError {
        TicketError::Failed(error.to_string())
    }
}

impl From<vectispire_cp_issues::IssueError> for TicketError {
    fn from(error: vectispire_cp_issues::IssueError) -> TicketError {
        match error {
            vectispire_cp_issues::IssueError::NotFound(message) => TicketError::NotFound(message),
            vectispire_cp_issues::IssueError::InvalidInput(message) => TicketError::InvalidInput(message),
            other => TicketError::Failed(other.to_string()),
        }
    }
}
