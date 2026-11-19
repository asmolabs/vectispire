//! The port an integration token's owner tells its change of state through — Java's `TokenAlert` published as an
//! application event, heard by `notifications`' `TokenAlerts` in the publisher's transaction (`MANDATORY`).
//!
//! **Why here**, for the reason [`crate::SecurityEvents`] gives: `tickets` and `forges` raise an alert without listing
//! `notifications`, and `notifications` hears it without listing them. The alert becomes outbox rows — its audit entry
//! and one message per configured channel — in the raiser's transaction, so the record that it was said and every
//! effect commit together, or not at all.

use futures_util::future::BoxFuture;
use vectispire_cp_db::Tx;
use vectispire_domain::notifications::TokenAlert;

use crate::security_events::RaiseError;

/// Where a token's change of state goes.
pub trait TokenAlertSink: Send + Sync {
    /// Queued in **the caller's** transaction. A failure is the caller's to roll back with: the change is then not
    /// recorded as said either, and the next turn says it.
    fn changed<'a>(&'a self, tx: &'a mut Tx, alert: &'a TokenAlert) -> BoxFuture<'a, Result<(), RaiseError>>;
}

/// Nobody listening: the alert is dropped. For module tests; the binary hands `notifications`' in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotTold;

impl TokenAlertSink for NotTold {
    fn changed<'a>(&'a self, _: &'a mut Tx, _: &'a TokenAlert) -> BoxFuture<'a, Result<(), RaiseError>> {
        Box::pin(async { Ok(()) })
    }
}
