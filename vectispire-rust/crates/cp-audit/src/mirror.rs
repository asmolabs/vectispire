//! The second copy of the log (`audit.internal.AuditMirror`): what lets a deletion the chain cannot see — the
//! last entry, a branch's tip — be one subtraction.
//!
//! **A trait here, the file writer elsewhere.** The writer is `vectispire-cp-runtime`'s `AuditMirror` (task 0.6,
//! the same NDJSON line in Jackson's bytes), and a module crate does not depend on the runtime: the binary
//! adapts one to the other. The entry below carries exactly the fields that line has.

/// A line of the mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorEntry {
    pub id: String,
    /// The canonical form the hash itself uses ([`crate::chain::canonical`]), so the mirror and the table
    /// cannot disagree about an instant merely because one printed it differently.
    pub timestamp: String,
    pub operation: String,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub description: Option<String>,
    pub previous_hash: Option<String>,
    pub entry_hash: String,
}

/// Where the mirror is written.
pub trait Mirror: Send + Sync + std::fmt::Debug {
    /// Appends an entry. **Must not panic**: the caller is recording something that already happened. `false`
    /// when the line could not be written, so the caller can say so — the comparison will see it too.
    fn append(&self, entry: &MirrorEntry) -> bool;

    /// Whether a second copy exists at all.
    fn configured(&self) -> bool;

    /// Every entry hash the mirror holds, in the order written.
    fn entry_hashes(&self) -> Result<Vec<String>, String>;
}

/// No mirror: every append succeeds and nothing is held — reported as "not configured", never as "0 missing".
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMirror;

impl Mirror for NoMirror {
    fn append(&self, _entry: &MirrorEntry) -> bool {
        true
    }

    fn configured(&self) -> bool {
        false
    }

    fn entry_hashes(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
}

/// What the table and the mirror say about each other (`AuditLogService.MirrorComparison`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorComparison {
    /// False when no mirror is set up — reported rather than hidden.
    pub configured: bool,
    /// Entries the mirror holds and the table does not: the case the chain cannot see.
    pub missing_from_table: usize,
    /// Entries the table holds and the mirror does not: written before the mirror, while its disk was full, or
    /// by somebody who had the database and not the file — indistinguishable from here, and said so.
    pub missing_from_mirror: usize,
}
