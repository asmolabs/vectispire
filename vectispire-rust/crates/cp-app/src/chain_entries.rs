//! The chain's own entries (`ACCESS_DENIED`, `BEARER_TOKEN_THROTTLED`), written to the audit log as Java's filter
//! writes them: in the request, before the answer (plan, Phase 2 task 2.11).

use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, AuditOperation, Record, Signal};
use vectispire_cp_http::credentials::{AccessDenied, Audit};

/// Adapts the chain's `Audit` port to write into the control plane's `AuditLog`.
#[derive(Debug, Clone)]
pub struct ChainEntries(pub Arc<AuditLog>);

impl ChainEntries {
    fn write(&self, entry: AccessDenied, signal: Option<Signal>) {
        let record = Record {
            operation: AuditOperation::AccessDenied,
            resource_id: Some(entry.path),
            description: Some(entry.detail),
            user_id: entry.who,
            ip_address: Some(entry.address),
            user_agent: entry.user_agent,
            signal,
        };
        let log = self.0.clone();
        tokio::spawn(async move {
            log.record(record).await;
        });
    }
}

impl Audit for ChainEntries {
    fn access_denied(&self, entry: AccessDenied) {
        self.write(entry, None);
    }

    fn bearer_throttled(&self, entry: AccessDenied) {
        self.write(entry, Some(Signal("BEARER_TOKEN_THROTTLED")));
    }
}
