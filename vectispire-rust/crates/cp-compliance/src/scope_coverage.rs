//! How much of the certified scope this instance can see — Java's `ScopeCoverage`.
//!
//! **A tool measuring its own coverage always reports full coverage**: the assets a scope statement names and this
//! instance holds no row for have no row to be missing from. So the statement's own count is carried, and the
//! subtraction is the figure an assessment opens with.

use serde::{Deserialize, Serialize};

/// `declared_assets` is what the scope statement says it covers, zero meaning nobody has said; the rest describe the
/// targets marked in scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCoverage {
    pub declared_assets: i32,
    pub in_scope: i32,
    pub scanned_recently: i32,
    pub stale: i32,
    pub never_scanned: i32,
}

impl ScopeCoverage {
    /// Assets the scope statement claims that this instance holds no row for. **Zero when nobody has declared a
    /// count — not when the coverage is complete**; [`declared`](Self::declared) tells the two apart.
    pub fn unaccounted_for(&self) -> i32 {
        if self.declared_assets <= 0 { 0 } else { self.declared_assets.wrapping_sub(self.in_scope).max(0) }
    }

    /// Whether anybody has said what the scope covers.
    pub fn declared(&self) -> bool {
        self.declared_assets > 0
    }
}
