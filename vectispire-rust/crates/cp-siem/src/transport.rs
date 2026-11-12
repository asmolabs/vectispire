//! What sends one event, as the services see it: the contract [`crate::SiemSender`] keeps, and the failure it answers.
//!
//! A trait rather than the sender itself because the services are held to Java's through their collaborators, as
//! `SiemModuleReferenceSetTest` holds Java's over a mocked `SiemSender`: the save's stop notice and the connection
//! test are compared with what Java handed its sender. The real sender is what the composition hands them, and what
//! the delivery, the save and the test reach real sockets with in this crate's suites.

use futures_util::future::BoxFuture;
use vectispire_cp_outbound::UnsafeUrl;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CefEvent, CollectorCa, SiemEndpoint};

/// Why an event did not leave.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The outbound policy refused the destination — Java's `UnsafeUrlException`.
    #[error("{0}")]
    Refused(UnsafeUrl),
    /// Anything else. `kind` is the simple name of the exception Java's sender throws for the same failure
    /// (`OutboundFailureException`, `OutboundStatusException`), so that the outbox's `last_error` reads the same
    /// whichever control plane wrote it.
    #[error("{kind}: {message}")]
    Failed { kind: String, message: String },
}

impl SendError {
    pub fn failed(kind: &str, message: impl Into<String>) -> SendError {
        SendError::Failed { kind: kind.to_owned(), message: message.into() }
    }

    /// The exception's simple name Java would record.
    pub fn kind(&self) -> &str {
        match self {
            SendError::Refused(_) => "UnsafeUrlException",
            SendError::Failed { kind, .. } => kind,
        }
    }

    /// Its message, as Java's `getMessage()`.
    pub fn message(&self) -> &str {
        match self {
            SendError::Refused(refused) => &refused.0,
            SendError::Failed { message, .. } => message,
        }
    }
}

/// Sends one CEF event to a destination.
pub trait Transport: Send + Sync {
    /// `header` is sent with a webhook only, and only when it is not blank; `ca` is read for syslog over TLS only.
    fn send<'a>(
        &'a self,
        endpoint: &'a SiemEndpoint,
        header: Option<&'a Secret>,
        ca: Option<&'a CollectorCa>,
        event: &'a CefEvent,
    ) -> BoxFuture<'a, Result<(), SendError>>;
}

/// Whether an administrator has opened the internal network to the export (`siem_allow_private_destination`), read at
/// every send as Java reads it.
pub trait PrivateDestinations: Send + Sync {
    fn allowed(&self) -> BoxFuture<'_, Result<bool, String>>;
}

impl PrivateDestinations for Settings {
    fn allowed(&self) -> BoxFuture<'_, Result<bool, String>> {
        Box::pin(async move {
            self.is_enabled(Setting::SiemAllowPrivateDestination).await.map_err(|error| error.to_string())
        })
    }
}
