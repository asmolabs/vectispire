//! `CollectorCa`: the certificate authorities a syslog-over-TLS collector is verified against, in place of the
//! public roots.
//!
//! A collector on an internal network carries a certificate from the organisation's own CA, and trusting that CA
//! for every outbound connection — trackers, models, webhooks — to reach one collector is the widening this
//! avoids: pinned here, it is trusted for this one connection, and a certificate some public CA issued for the
//! collector's name does not pass. **What is refused, and why at the save**, is [`PinnedCa`]'s rule, which the
//! forge connections share; this keeps the SIEM's wording. A CA is public: it is stored as written.

use crate::bounded_text::Refused;
use crate::instant::Instant;
use crate::pinned_ca::{Anchor, PinnedCa, Subject};

pub use crate::pinned_ca::{MAX_CERTIFICATES, MAX_LENGTH};

/// How the refusals name this field.
pub const SUBJECT: Subject = Subject { field: "The collector CA", server: "the collector" };

/// A collector's bundle, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorCa(PinnedCa);

impl CollectorCa {
    /// Reads a bundle and checks it is usable at `now`, or refuses it in words meant for whoever pasted it.
    pub fn parse(pem: Option<&str>, now: Instant) -> Result<CollectorCa, Refused> {
        PinnedCa::parse(pem, now, &SUBJECT).map(CollectorCa)
    }

    /// Reads a bundle, checking its shape but not its dates — for describing a stored one, which may have expired
    /// since it was saved and must still be shown so that somebody replaces it.
    pub fn read(pem: Option<&str>) -> Result<CollectorCa, Refused> {
        PinnedCa::read(pem, &SUBJECT).map(CollectorCa)
    }

    /// This bundle, when every certificate of it is valid at `now`.
    pub fn require_current(self, now: Instant) -> Result<CollectorCa, Refused> {
        self.0.require_current(now, &SUBJECT)?;
        Ok(self)
    }

    /// The bundle as stored, trimmed.
    pub fn pem(&self) -> &str {
        self.0.pem()
    }

    /// Each certificate, in order; its DER is what the TLS stack is handed.
    pub fn anchors(&self) -> &[Anchor] {
        self.0.anchors()
    }

    /// The first certificate's subject: what the screen shows to say which CA is pinned.
    pub fn subject(&self) -> &str {
        self.0.subject()
    }

    /// The earliest expiry of the bundle: past it, the collector is no longer reachable.
    pub fn not_after(&self) -> Instant {
        self.0.not_after()
    }

    /// The rule underneath, for the sender that pins it.
    pub fn as_pinned(&self) -> &PinnedCa {
        &self.0
    }
}
