//! A clone that did not happen, and the sentence that says what to do about it —
//! `CloneFailureException` and `GitClone.sentence`.
//!
//! **The kind decides the scan's fate, the message only informs.** A changed host key and a dropped
//! connection both end as a failed clone; the scan must give up on one and retry the other. The kind
//! is decided from what is typed — libgit2's error class, the HTTP status this crate's own transport
//! read, the host-key check this crate made — never from a message's words, which only choose the
//! sentence when nothing typed does.

use vectispire_domain::FailureKind;
use vectispire_domain::failure::Classified;

/// What stopped the clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The server's host key is not the one recorded or pinned for it.
    HostKey,
    /// The forge refused the credential, or asked for one and none was given.
    Authentication,
    /// The forge says the repository does not exist, or is not this credential's to see.
    NotFound,
    /// The repository exists and the branch does not.
    BranchAbsent,
    /// The credential held cannot be used: a key that does not parse, a token bound to another host.
    Credential,
    /// The clone's own guard refused where the URL leads: its form, a link-local host, a redirect.
    UrlRefused,
    /// The forge did not answer in time.
    Timeout,
    /// The host could not be reached.
    Network,
    /// The forge answered with an error of its own — a 5xx, a 429.
    Unavailable,
    /// Nothing typed says which: transient, as every failure is when in doubt.
    Unclassified,
}

impl Kind {
    /// The Java enum's name, as a failure report carries it.
    pub fn wire_name(self) -> &'static str {
        match self {
            Kind::HostKey => "HOST_KEY",
            Kind::Authentication => "AUTHENTICATION",
            Kind::NotFound => "NOT_FOUND",
            Kind::BranchAbsent => "BRANCH_ABSENT",
            Kind::Credential => "CREDENTIAL",
            Kind::UrlRefused => "URL_REFUSED",
            Kind::Timeout => "TIMEOUT",
            Kind::Network => "NETWORK",
            Kind::Unavailable => "UNAVAILABLE",
            Kind::Unclassified => "UNCLASSIFIED",
        }
    }

    pub fn failure_kind(self) -> FailureKind {
        match self {
            Kind::Timeout | Kind::Network | Kind::Unavailable | Kind::Unclassified => FailureKind::Transient,
            _ => FailureKind::Permanent,
        }
    }
}

/// A failed clone: its kind, the sentence a person reads, and the transport's own text for whoever
/// needs the detail — with any credential in a URL masked in both.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CloneError {
    pub kind: Kind,
    pub message: String,
    pub detail: String,
}

impl CloneError {
    pub fn new(kind: Kind, message: impl Into<String>) -> CloneError {
        CloneError { kind, message: message.into(), detail: String::new() }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> CloneError {
        self.detail = detail.into();
        self
    }
}

impl Classified for CloneError {
    fn failure_kind(&self) -> FailureKind {
        self.kind.failure_kind()
    }
}
