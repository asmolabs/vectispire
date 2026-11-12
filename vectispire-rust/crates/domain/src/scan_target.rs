//! `ScanTarget`: what a scan runs against — a source repository or a container image.
//!
//! An enum rather than two nullable ids, as Java's sealed interface is: the NestJS original carried
//! both side by side, and the fingerprint got repository `0` right only because it tested `!= null`.

use serde::Serialize;

/// A repository or a container image, by its row id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ScanTarget {
    Repository(i64),
    Container(i64),
}

impl ScanTarget {
    /// The stable text form that enters an issue's fingerprint: `repo:<id>` or `container:<id>`,
    /// the id in Java's `long` decimal form. **A data contract** — changing a prefix recreates every
    /// issue of every target, triage lost.
    pub fn fingerprint_key(self) -> String {
        match self {
            ScanTarget::Repository(id) => format!("repo:{id}"),
            ScanTarget::Container(id) => format!("container:{id}"),
        }
    }

    /// The row id, whichever kind of target it names.
    pub fn id(self) -> i64 {
        match self {
            ScanTarget::Repository(id) | ScanTarget::Container(id) => id,
        }
    }
}
