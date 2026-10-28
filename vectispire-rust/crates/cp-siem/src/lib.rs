//! The control plane's SIEM module — `core.siem` (plan, Phase 4 task 4.2, second stage): its services, not yet its
//! routes nor its place in the binary (the third stage).
//!
//! - [`SiemExporterService`] — the singleton configuration: read, checked and saved (the header encrypted at rest
//!   under its own context, the collector CA read as pasted, a new destination not inheriting the old header), the
//!   stop notice to a collector being left, and the connection test's outcome-only answer.
//! - [`SiemEvents`] — the audit log's [`vectispire_cp_audit::Listener`] and [`vectispire_cp_audit::ChainBrokenListener`]:
//!   an entry that signals an event queues it in the entry's own transaction, as an outbox row of type [`TYPE`].
//! - [`SiemDelivery`] — the outbox's [`vectispire_cp_outbox::OutboxHandler`] for that type: the destination read at
//!   send time, gone or retried.
//! - [`SiemSender`] and [`SyslogSender`] — the transports: a webhook through the outbound guard and the pinned HTTP
//!   sender, syslog over UDP, TCP or TLS to the address the guard checked, octet-counted on a stream, with the
//!   collector's own CA in place of the runtime's trust when one is pinned.
//!
//! What uses what is Java's `package-info`: nothing above the foundation for the services (audit, outbox, outbound,
//! settings, crypto, all shared), `access::security` for the routes when they come. The domain — the event catalogue,
//! the CEF line, the syslog frame, the endpoint and the CA — is `vectispire_domain::siem`, which the modules that raise
//! events share.

#![forbid(unsafe_code)]

mod config;
mod delivery;
mod error;
mod events;
mod internal;
mod persistence;
mod transport;

pub use config::{
    AUTH_HEADER_CONTEXT, MAX_AUTH_HEADER_LENGTH, MAX_ENDPOINT_LENGTH, NOT_DELIVERED, REFUSED_BY_POLICY,
    SiemConfigUpdate, SiemConfigView, SiemExporterService, TestResult,
};
pub use delivery::SiemDelivery;
pub use error::SiemError;
pub use events::{
    MAX_MESSAGE_LENGTH, QueueError, QueuedEvent, SiemEvents, TYPE, Unreadable, bounded, of_epoch_milli,
    signalled_by_entry,
};
pub use internal::sender::{LABEL, SiemSender, TIMEOUT, body};
pub use internal::syslog::{MAX_DATAGRAM, SyslogSender, TrustUnreadable};
pub use transport::{PrivateDestinations, SendError, Transport};
