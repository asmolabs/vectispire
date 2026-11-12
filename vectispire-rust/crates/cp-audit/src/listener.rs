//! What acts on an entry once it exists (`AuditLogService.Listener`) — the SIEM export's hook — and what hears a
//! verification that failed (`AuditChainBroken`).

use futures_util::future::BoxFuture;
use time::OffsetDateTime;
use vectispire_cp_db::Tx;

use crate::record::Record;

/// What a listener refused with. Anything: the log only needs to know that it failed.
pub type ListenerError = Box<dyn std::error::Error + Send + Sync>;

/// Something that acts on an entry.
///
/// **In the entry's transaction first, after its commit only if that failed** (decision 0033). A listener that
/// acted only after the commit made a stop between the commit and its own transaction a lost effect — every SIEM
/// event an entry signals left that way. So [`Listener::recorded_in_transaction`] writes in the entry's
/// transaction, and the entry and what it causes commit together.
///
/// **A listener that fails still cannot cost the entry.** Its failure rolls the transaction back, and the entry
/// is written again on its own, with [`Listener::recorded`] called after that commit: the old path, kept as the
/// fallback. The two are never both called for one entry.
pub trait Listener: Send + Sync {
    /// Inside the entry's transaction. Writes only in it; an error aborts that transaction.
    fn recorded_in_transaction<'a>(
        &'a self,
        entry: &'a Record,
        at: OffsetDateTime,
        tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>>;

    /// After the entry's commit, when [`Listener::recorded_in_transaction`] could not be. Its error is logged and
    /// stops there: the entry is committed already.
    fn recorded<'a>(&'a self, entry: &'a Record, at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>>;

    /// For the error logs, as Java names the listener's class.
    fn name(&self) -> &str;
}

/// A verification found the trail tampered with: the chain breaks, or the mirror holds entries the table lost.
///
/// **Owned by audit, heard by the SIEM**, so the dependency points one way: the SIEM knows this type, the audit
/// log knows nobody (decision 0026).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainBroken {
    /// The entry where the chain stops verifying; `None` when the chain holds and only the mirror disagrees.
    pub broken_at: Option<String>,
    /// Entries the mirror holds and the table does not.
    pub missing_from_table: usize,
}

impl AuditChainBroken {
    /// Worded for a SOC analyst reading one line, who has neither the screen nor the table.
    pub fn describe(&self) -> String {
        match &self.broken_at {
            Some(at) => format!("The audit chain breaks at entry {at}"),
            None => format!(
                "{} entr{} held by the mirror are missing from the table",
                self.missing_from_table,
                if self.missing_from_table == 1 { "y" } else { "ies" }
            ),
        }
    }
}

/// Hears a broken verification — **synchronously, every time one finds it**, not once: a SOC deduplicates; what
/// it cannot do is hear about a tampering that was reported to one screen and nowhere else.
pub trait ChainBrokenListener: Send + Sync {
    fn chain_broken<'a>(&'a self, event: &'a AuditChainBroken) -> BoxFuture<'a, ()>;
}
