//! The control plane's audit module — the Rust of `core.audit` (plan, Phase 1 task 1.6).
//!
//! - [`AuditLog`] writes the log and verifies it (`AuditLogService`): each entry in its own transaction, under
//!   the chain's one-row lock, chained onto the head read under that lock, its listeners in its transaction
//!   with the entry-alone fallback, its mirror line written before the commit. [`AuditLog::record`] never
//!   fails; [`AuditLog::append`] says why it did.
//! - [`AuditLogQuery`] reads it (`AuditLogQueryService`): the filtered page, the counts the digests use, the
//!   evidence bundle's JSON lines, and the integrity report that tells the SIEM of a break.
//! - [`chain`] is the integrity chain itself, the part every installation's existing log depends on: an entry
//!   hashed here is hashed as Java hashes it (`reference/audit/chain.json`), and a log Java started continues
//!   here and back (`tests/oracle.rs`).
//!
//! The mirror's file writer and the SIEM are outside the module: [`Mirror`], [`Listener`] and
//! [`ChainBrokenListener`] are what the binary plugs them into.

#![forbid(unsafe_code)]

pub mod chain;
mod export;
pub mod listener;
mod log;
pub mod mirror;
pub mod operation;
mod persistence;
mod query;
pub mod record;
pub mod text;

pub use listener::{AuditChainBroken, ChainBrokenListener, Listener, ListenerError};
pub use log::{AuditError, AuditLog};
pub use mirror::{Mirror, MirrorComparison, MirrorEntry, NoMirror};
pub use operation::AuditOperation;
pub use query::{AuditLogQuery, Entries, Integrity, JsonLines, QueryError, SEARCH_MAX, bounded_search, iso_instant};
pub use record::{Clock, Record, RequestActor, Signal, StoredEntry, SystemClock};

/// The bytes the evidence bundle holds for one row — exposed for the bundle's own module and for the tests that
/// hold them to Java's.
pub fn entity_document(entry: &StoredEntry) -> String {
    export::entity_document(entry)
}
