//! Ports what `rules` asks of other modules: inventory package URLs and issue rule counts.
//!
//! Each has a named stand-in until the respective module is ported in Phase 3.

use std::collections::BTreeMap;
use vectispire_cp_http::credentials::BoxFuture;

pub type PortError = Box<dyn std::error::Error + Send + Sync>;
pub type TargetPurl = (Option<i64>, Option<i64>, String);

/// What `rules` asks of `inventory`: distinct package URLs in the estate.
pub trait InventoryEcosystems: Send + Sync {
    /// Distinct package URLs across the entire estate inventory.
    fn distinct_purls(&self) -> BoxFuture<'_, Result<Vec<String>, PortError>>;

    /// Distinct package URLs grouped by target: `(repo_id, container_id, purl)`.
    fn distinct_purls_by_target(&self) -> BoxFuture<'_, Result<Vec<TargetPurl>, PortError>>;
}

/// `inventory`'s stand-in until Task 3.2: no package URL in inventory.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandInInventory;

impl InventoryEcosystems for StandInInventory {
    fn distinct_purls(&self) -> BoxFuture<'_, Result<Vec<String>, PortError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn distinct_purls_by_target(&self) -> BoxFuture<'_, Result<Vec<TargetPurl>, PortError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// What `rules` asks of `issues`: open SAST issues counted by rule identifier.
pub trait IssueRuleCounts: Send + Sync {
    /// Count of open SAST issues grouped by Semgrep rule identifier (`check_id`).
    fn open_sast_issues_by_rule(&self) -> BoxFuture<'_, Result<BTreeMap<String, i64>, PortError>>;
}

/// `issues`' stand-in until Task 3.4: no open issues in backlog.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandInIssues;

impl IssueRuleCounts for StandInIssues {
    fn open_sast_issues_by_rule(&self) -> BoxFuture<'_, Result<BTreeMap<String, i64>, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }
}
