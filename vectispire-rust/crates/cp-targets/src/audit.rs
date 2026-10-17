//! Where this module's entries go — the audit log, behind a port so the services can be driven without a chain.
//!
//! **Recorded after the write committed, never inside it**: the audit log opens its own transaction, and an entry
//! written inside the write's would describe a write that may still roll back (Java's services say so beside each
//! `audit.record`).

use vectispire_cp_audit::{AuditLog, Record};
use vectispire_cp_http::credentials::BoxFuture;

/// `AuditLogService.record`: never fails the caller; the log logs its own failures.
pub trait AuditSink: Send + Sync {
    fn record(&self, entry: Record) -> BoxFuture<'_, ()>;
}

impl AuditSink for AuditLog {
    fn record(&self, entry: Record) -> BoxFuture<'_, ()> {
        Box::pin(AuditLog::record(self, entry))
    }
}

/// `SecurityEventType.ACCESS_GRANT_CHANGED`, which a deletion's entry signals when grants went with the target.
pub const ACCESS_GRANT_CHANGED: vectispire_cp_audit::Signal = vectispire_cp_audit::Signal("ACCESS_GRANT_CHANGED");
