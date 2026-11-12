//! What the administration services share — the refusals the routes map, and the audit entry each gesture writes.
//!
//! The services themselves are [`crate::teams`] (`TeamAdministrationService`, `TeamChannels`),
//! [`crate::account_targets`] (the grants half of `AccountAdministrationService`), [`crate::api_key_administration`]
//! (`ApiKeyAdministrationService`) and [`crate::account_names`] (`AccountNames`, `AccountDirectory`).

use crate::accounts::{Audit, AuditOperation, AuditRecord, RequestActor};
use crate::visibility::AccessError;

/// Why an administration gesture was refused, or could not be made — what the routes of task 1.7 map.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// `InvalidInputException`: 400, the message shown as it is.
    #[error("{0}")]
    InvalidInput(String),
    /// `InvalidApiKeyException`: 400 as well, in its own words.
    #[error("{0}")]
    InvalidApiKey(String),
    /// `NotFoundException`: 404, the message as Java writes it ("Team not found.", "No repository with id 3.").
    #[error("{0}")]
    NotFound(String),
    /// `UnsafeUrlException`: 422 — the URL guard refused the destination.
    #[error("{0}")]
    UnsafeUrl(String),
    /// A statement failed, or a port (the targets, the settings) could not answer: a 500, **never read as "absent"
    /// or "nothing"** (decision 0007).
    #[error("the administration could not be read or written: {0}")]
    Failed(String),
}

impl From<crate::persistence::StoreError> for AdminError {
    fn from(error: crate::persistence::StoreError) -> AdminError {
        AdminError::Failed(error.to_string())
    }
}

impl From<crate::credentials::StoreError> for AdminError {
    fn from(error: crate::credentials::StoreError) -> AdminError {
        AdminError::Failed(error.to_string())
    }
}

impl From<crate::accounts::StoreError> for AdminError {
    fn from(error: crate::accounts::StoreError) -> AdminError {
        AdminError::Failed(error.to_string())
    }
}

impl From<AccessError> for AdminError {
    fn from(error: AccessError) -> AdminError {
        AdminError::Failed(error.to_string())
    }
}

/// `AuditLogService.Record(operation, resource, description, actor…)` — the entry every gesture writes **after** its
/// transaction, as Java writes it after the repository call returns.
pub(crate) async fn record<A: Audit + Sync>(
    audit: &A,
    actor: &RequestActor,
    operation: AuditOperation,
    resource: String,
    description: String,
) {
    audit
        .record(AuditRecord {
            operation,
            resource,
            description,
            username: actor.username.clone(),
            ip_address: actor.ip_address.clone(),
            user_agent: actor.user_agent.clone(),
            signal: None,
        })
        .await;
}
