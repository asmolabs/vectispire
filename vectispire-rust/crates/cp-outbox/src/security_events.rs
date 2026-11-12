//! The port a module raises a security event through — Java's `SecurityEventRaised` and `SecurityEventRaisedApart`.
//!
//! **Why here.** On the Java side the two records sit in `common.domain.siem` and travel as Spring application events,
//! so that `issues`, `gate` and `threatintel` raise an event without listing the SIEM among their dependencies; the
//! SIEM's listener joins the publisher's transaction (`MANDATORY`). Rust has no event bus, so the publisher becomes a
//! trait the SIEM module implements and the binary hands in. It cannot live in `vectispire_domain`, which the agent
//! links and which must not name a transaction; nor in `cp-siem`, which would put the export back among the raisers'
//! dependencies. The outbox is the shared module the event becomes a row of, in the raiser's transaction — what
//! decision 0033 gives it — and every module may use a shared one without a line in its edges.
//!
//! What is queued, and whether anything is (the export off, below the minimum severity), is the implementation's
//! rule, not the raiser's: a raiser builds the event and hands it over.

use futures_util::future::BoxFuture;
use vectispire_cp_db::Tx;
use vectispire_domain::siem::CefEvent;

/// Why an event raised in a transaction was not queued: the caller rolls back with it, as Java's listener exception
/// rolls back the publisher.
pub type RaiseError = Box<dyn std::error::Error + Send + Sync>;

/// Where a module's security events go.
pub trait SecurityEvents: Send + Sync {
    /// `SecurityEventRaised`: queued in **the caller's** transaction, so the event commits with what it describes or
    /// not at all. A failure is the caller's to roll back with.
    fn raise<'a>(&'a self, tx: &'a mut Tx, event: &'a CefEvent) -> BoxFuture<'a, Result<(), RaiseError>>;

    /// `SecurityEventRaisedApart`: queued in a transaction of its own, for a caller whose state has already committed
    /// — the fallback where the two could not be written together. **Never fails**: the export logs what it cannot
    /// queue. Called outside any open write transaction.
    fn raise_apart<'a>(&'a self, event: &'a CefEvent) -> BoxFuture<'a, ()>;
}

/// No export: every event is dropped. For the module tests and the stand-ins that compose a raiser without the SIEM;
/// the binary hands the SIEM module's events in, and `cp-app`'s SIEM composition test holds it to that.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotExported;

impl SecurityEvents for NotExported {
    fn raise<'a>(&'a self, _: &'a mut Tx, _: &'a CefEvent) -> BoxFuture<'a, Result<(), RaiseError>> {
        Box::pin(async { Ok(()) })
    }

    fn raise_apart<'a>(&'a self, _: &'a CefEvent) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}
