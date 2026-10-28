//! The SIEM export's domain — `common.domain.siem`: the event catalogue, the CEF line, the syslog frame, the
//! endpoint and collector CA an operator types, and which events pass the configured minimum.
//!
//! Here rather than in the export's own crate so that a module raising an event (`issues`, `gate`, the threat
//! feed) builds a [`CefEvent`] without depending on the export, as the Java types sit in `vectispire-common`.
//! Java's `SecurityEventRaised` and `SecurityEventRaisedApart` are Spring application events and are not ported
//! here: the export's crate replaces them with a trait its raisers are handed.
//!
//! **Everything that leaves the system is Java's byte for byte** — the CEF line, the syslog frame, the wire
//! names, the refusals — and held to `reference/siem/` (`SiemReferenceSetTest`).

pub mod cef;
pub mod collector_ca;
pub mod endpoint;
pub mod event_type;
pub mod protocol;
pub mod severity_filter;
pub mod syslog;
pub mod triage_signals;

pub use cef::{CefEvent, CefEventBuilder, InvalidEvent};
pub use collector_ca::CollectorCa;
pub use endpoint::SiemEndpoint;
pub use event_type::{Outcome, Placement, SecurityEventType, signalled_by};
pub use protocol::SiemProtocol;
