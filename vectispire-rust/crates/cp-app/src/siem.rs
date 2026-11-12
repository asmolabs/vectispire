//! The SIEM export as the binary composes it (task 4.2, third stage) — one function each for the pieces, so that
//! `main` and `tests/siem_composition.rs` build the same thing: a wiring that is only in `main` is a wiring no test
//! sees, which is how `IssueTriageService.expireStale` went uncalled.
//!
//! **What goes where.**
//!
//! - [`SiemEvents`] is the audit log's [`vectispire_cp_audit::Listener`] (an entry that signals an event queues it in
//!   the entry's own transaction), the verification's [`vectispire_cp_audit::ChainBrokenListener`], and the
//!   [`SecurityEvents`] port the issues and the gate raise their events through.
//! - [`SiemDelivery`] is the outbox's handler for `siem_event` — in [`crate::maintenance::outbox_registry`].
//! - [`SiemSender`] reaches the collector: a webhook through the outbound guard (the reserved endpoints included) and
//!   `PinnedHttpSender`, syslog through the same guard; the private-destination switch read from the settings at every
//!   send; the runtime's trust from `VECTISPIRE_TLS_CA_BUNDLE`.
//!
//! **Two outboxes, one table.** The audit log needs its listeners when it is built, the listener needs an outbox to
//! queue in, and the relaying outbox needs its registry, whose agents' handler writes to the audit log: a cycle. It is
//! broken where nothing is lost — [`SiemEvents`] only ever *enqueues*, which reads no handler, so it is handed an
//! outbox over the same table with an empty registry; the relaying outbox, built after the audit log, holds every
//! handler. A row queued by one is relayed by the other: they are the same `t_outbox_message`.

use std::sync::Arc;

use vectispire_cp_audit::Clock;
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_outbox::{Outbox, Registry, SecurityEvents};
use vectispire_cp_siem::{SiemDelivery, SiemEvents, SiemExporterService, SiemSender, SyslogSender, TrustUnreadable};
use vectispire_tls::TlsTrust;

/// The module's pieces the rest of the composition is handed.
#[derive(Debug, Clone)]
pub struct Siem {
    /// The audit log's listener and chain-broken listener, and the issues' and gate's [`SecurityEvents`].
    pub events: Arc<SiemEvents>,
    /// The `siem_event` handler, for the outbox's registry.
    pub delivery: Arc<SiemDelivery>,
    /// The transport the delivery, the stop notice and the connection test share.
    pub sender: Arc<SiemSender>,
}

impl Siem {
    /// The events, as the port the raising modules are handed.
    #[must_use]
    pub fn security_events(&self) -> Arc<dyn SecurityEvents> {
        self.events.clone()
    }
}

/// Everything [`compose`] needs from the binary.
#[derive(Debug, Clone)]
pub struct SiemSetup {
    pub db: Db,
    /// The guard the binary built at start, with the reserved endpoints (the database, the Docker daemon, the
    /// Kubernetes API) in it.
    pub guard: OutboundUrlGuard,
    /// The runtime's trust: the authorities compiled in, or `VECTISPIRE_TLS_CA_BUNDLE`'s alone.
    pub trust: TlsTrust,
    pub encryption: Arc<Encryption>,
    /// `ProductVersion`: the CEF header's device version.
    pub version: Option<String>,
}

/// The sender, the delivery and the events — before the audit log, which takes the events as its listener.
///
/// # Errors
/// The runtime's bundle could not be read for syslog over TLS: refused at start, as an unreadable trust is.
pub fn compose(setup: SiemSetup, clock: Arc<dyn Clock>) -> Result<Siem, TrustUnreadable> {
    let sender = Arc::new(SiemSender::new(
        setup.guard,
        PinnedHttpSender::new(setup.trust.clone()),
        SyslogSender::new(&setup.trust)?,
        Arc::new(vectispire_cp_settings::Settings::new(setup.db.clone())),
        setup.version,
    ));
    let delivery =
        Arc::new(SiemDelivery::new(setup.db.clone(), sender.clone(), setup.encryption.clone(), clock.clone()));
    // Enqueue only: see the module's documentation for why this outbox has no handler.
    let queue = Arc::new(Outbox::on_database(
        setup.db.clone(),
        Registry::new(Vec::new(), Vec::new()),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));
    let events = Arc::new(SiemEvents::new(setup.db, queue, clock));
    Ok(Siem { events, delivery, sender })
}

/// The configuration's service — after the audit log, which it records its saves in.
#[must_use]
pub fn service(
    siem: &Siem,
    db: Db,
    encryption: Arc<Encryption>,
    audit: vectispire_cp_audit::AuditLog,
    clock: Arc<dyn Clock>,
) -> Arc<SiemExporterService> {
    Arc::new(SiemExporterService::new(db, siem.sender.clone(), encryption, audit, clock))
}

/// The audit log's listeners: the SIEM's, which queues the events the entries signal.
#[must_use]
pub fn audit_listeners(siem: &Siem) -> Vec<Arc<dyn vectispire_cp_audit::Listener>> {
    vec![siem.events.clone()]
}

/// The verification's chain-broken listeners: the SIEM's, which raises `AUDIT_CHAIN_BROKEN`.
#[must_use]
pub fn chain_broken_listeners(siem: &Siem) -> Vec<Arc<dyn vectispire_cp_audit::ChainBrokenListener>> {
    vec![siem.events.clone()]
}
