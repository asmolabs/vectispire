//! What compliance reads of modules it does not depend on: the deployment's own controls — encryption, the audit
//! log's mirror and chain, the sign-in doors and the second factor's reach — and which targets hold a component
//! inventory. Behind ports so that the crate stays clear of the crypto, access and inventory crates' generic services;
//! the binary composes the answers from them (`cp-app`'s `compliance` module).

use std::collections::BTreeSet;

use crate::decisions::PlatformPosture;
use vectispire_cp_db::ScanTarget;
use vectispire_cp_http::credentials::BoxFuture;

/// The deployment's controls, read fresh on every evaluation: settings an administrator changes, and a report built
/// from a cached copy would describe a configuration that no longer exists.
pub trait Platform: Send + Sync {
    /// `ComplianceService.platformPosture`: the password accounts read only where they decide something — with an
    /// identity provider the ceiling does not read them, and they are `(0, 0)`.
    fn posture(&self) -> BoxFuture<'_, Result<PlatformPosture, String>>;

    /// `AuditLogService.recentEntriesMatchTheirHashes`: bounded, not the full verification — that is
    /// `/audit-log/verify`, which somebody asks for; this runs on every compliance page.
    fn audit_chain_valid(&self) -> BoxFuture<'_, Result<bool, String>>;
}

/// `ComplianceService.targetsWithInventory`: the targets whose scans produced a component inventory. **No visibility**:
/// the caller intersects it with its own, already narrowed, posture.
pub trait Inventories: Send + Sync {
    fn targets_with_inventory(&self) -> BoxFuture<'_, Result<BTreeSet<ScanTarget>, String>>;
}
