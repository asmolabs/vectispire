//! The audit module's mirror, written by the runtime's file writer.
//!
//! **One writer, two crates.** The NDJSON line in Jackson's bytes, the append-only open per entry and the reading
//! back are `vectispire-cp-runtime`'s `AuditMirror` (task 0.6); the audit module only says when a line is due,
//! through its `Mirror` seam — a module crate does not depend on the runtime (`cp-arch-tests`' `edges.toml`). The
//! binary, which may use both, is where they meet: this adapter, and nothing else, so the line is written in one
//! place and cannot drift between a copy here and a copy there.

use vectispire_cp_audit::{Mirror, MirrorEntry};
use vectispire_cp_runtime::audit_mirror::{AuditMirror, Entry};

/// The file `vectispire.audit.mirror-path` names, or no mirror when it names none.
#[derive(Debug, Clone)]
pub struct FileMirror(AuditMirror);

impl FileMirror {
    /// From the setting as the runtime read it: blank is no mirror, which the integrity report says rather than
    /// reporting "0 missing" of a copy that does not exist.
    pub fn configured(path: Option<&str>) -> FileMirror {
        FileMirror(AuditMirror::configured(path))
    }
}

impl Mirror for FileMirror {
    fn append(&self, entry: &MirrorEntry) -> bool {
        self.0.append(&line(entry))
    }

    fn configured(&self) -> bool {
        self.0.is_configured()
    }

    fn entry_hashes(&self) -> Result<Vec<String>, String> {
        self.0.entry_hashes()
    }
}

/// Field for field: both are the Java record `AuditMirror.Entry`, in its order.
fn line(entry: &MirrorEntry) -> Entry {
    Entry {
        id: entry.id.clone(),
        timestamp: entry.timestamp.clone(),
        operation: entry.operation.clone(),
        resource_id: entry.resource_id.clone(),
        user_id: entry.user_id.clone(),
        ip_address: entry.ip_address.clone(),
        user_agent: entry.user_agent.clone(),
        description: entry.description.clone(),
        previous_hash: entry.previous_hash.clone(),
        entry_hash: entry.entry_hash.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str, previous: Option<&str>) -> MirrorEntry {
        MirrorEntry {
            id: "0b0c5e8e-5f7a-4f4e-9d38-3c2f1f0a9b11".to_owned(),
            timestamp: "2026-10-17T08:00:00.123Z".to_owned(),
            operation: "SETTING_UPDATED".to_owned(),
            resource_id: Some("sast_enabled".to_owned()),
            user_id: Some("ciso".to_owned()),
            ip_address: Some("203.0.113.9".to_owned()),
            user_agent: None,
            description: Some("sast_enabled = true".to_owned()),
            previous_hash: previous.map(str::to_owned),
            entry_hash: hash.to_owned(),
        }
    }

    #[test]
    fn the_audit_log_s_line_is_the_runtime_s_line_in_every_field() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.ndjson");
        let mirror: &dyn Mirror = &FileMirror::configured(path.to_str());
        assert!(mirror.configured());
        assert!(mirror.append(&entry("h1", None)));
        assert!(mirror.append(&entry("h2", Some("h1"))));
        let written = std::fs::read_to_string(&path).unwrap();
        // Each field in its own place: a field crossed with another, or dropped, changes this line.
        assert_eq!(
            written.lines().nth(1).unwrap(),
            "{\"id\":\"0b0c5e8e-5f7a-4f4e-9d38-3c2f1f0a9b11\",\"timestamp\":\"2026-10-17T08:00:00.123Z\",\
             \"operation\":\"SETTING_UPDATED\",\"resourceId\":\"sast_enabled\",\"userId\":\"ciso\",\
             \"ipAddress\":\"203.0.113.9\",\"userAgent\":null,\"description\":\"sast_enabled = true\",\
             \"previousHash\":\"h1\",\"entryHash\":\"h2\"}"
        );
        assert_eq!(mirror.entry_hashes(), Ok(vec!["h1".to_owned(), "h2".to_owned()]));
    }

    #[test]
    fn no_path_is_no_mirror_and_says_so() {
        let mirror = FileMirror::configured(Some("  "));
        assert!(!mirror.configured());
        assert!(mirror.append(&entry("h", None)), "nothing to write is not a failure");
        assert_eq!(mirror.entry_hashes(), Ok(Vec::new()));
    }
}
