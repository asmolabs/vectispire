//! The audit mirror as a file — `FileAuditMirror`: one JSON object per line, appended, never rewritten.
//!
//! **Why NDJSON and not a JSON array.** An array has to be closed, so every append means rewriting the end
//! of the file — and a process killed mid-write leaves a document no parser will read, which is to say an
//! audit copy destroyed by a restart. One object per line is append-only in the literal sense: the previous
//! bytes are never touched, a truncated last line costs one entry, and every log collector already knows
//! how to ship it.
//!
//! **Opened per append, and that is deliberate.** A long-lived handle would keep writing into a file that
//! log rotation has already moved, so entries would land in a file nobody reads while the current one
//! stays empty.
//!
//! **What is written is what is hashed, plus the two hashes** — in the Java record's field order, with
//! `null` for what is absent, in Jackson's escaping ([`crate::json`]): the point of the copy is to be
//! comparable with the table, and a field formatted differently here would make the comparison report
//! differences that are not ones. A line the Java control plane wrote is read here, and the reverse.

use std::io::Write;
use std::path::PathBuf;

use crate::json;

/// One audit entry, as mirrored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
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

impl Entry {
    /// The line, without its terminator: `{"id":…,"timestamp":…,…,"previousHash":…,"entryHash":…}`.
    pub fn to_json(&self) -> String {
        json::object(&[
            ("id", json::string(&self.id)),
            ("timestamp", json::string(&self.timestamp)),
            ("operation", json::string(&self.operation)),
            ("resourceId", json::nullable(self.resource_id.as_deref())),
            ("userId", json::nullable(self.user_id.as_deref())),
            ("ipAddress", json::nullable(self.ip_address.as_deref())),
            ("userAgent", json::nullable(self.user_agent.as_deref())),
            ("description", json::nullable(self.description.as_deref())),
            ("previousHash", json::nullable(self.previous_hash.as_deref())),
            ("entryHash", json::string(&self.entry_hash)),
        ])
    }
}

/// Where the audit trail is copied to, if anywhere.
#[derive(Clone, Debug)]
pub enum AuditMirror {
    /// No path configured: nothing to copy, and nothing failed.
    Disabled,
    File {
        path: PathBuf,
    },
}

impl AuditMirror {
    /// `vectispire.audit.mirror-path`, trimmed: empty is no mirror.
    pub fn configured(path: Option<&str>) -> AuditMirror {
        match path.map(|path| path.trim_matches(|c: char| c <= ' ')).filter(|path| !path.is_empty()) {
            Some(path) => AuditMirror::File { path: PathBuf::from(path) },
            None => AuditMirror::Disabled,
        }
    }

    pub fn is_configured(&self) -> bool {
        matches!(self, AuditMirror::File { .. })
    }

    /// Appends the entry. **Never an error to the caller**: a mirror that fails must not fail the action
    /// it describes. Logged loudly instead, and the verification then shows the entry present in the table
    /// and absent from the mirror — the honest description of what just happened. `true` when nothing
    /// failed, a disabled mirror included (an alarm on every entry about a feature nobody turned on would
    /// be worse than the silence).
    pub fn append(&self, entry: &Entry) -> bool {
        let AuditMirror::File { path } = self else { return true };
        match write_line(path, entry) {
            Ok(()) => true,
            Err(failure) => {
                tracing::error!("Audit entry {} could not be mirrored to {}: {failure}", entry.id, path.display());
                false
            }
        }
    }

    /// The hash of every entry the file holds, in order. A file that does not exist yet holds none — a
    /// freshly configured mirror has no file until the first entry — and a line that will not read is
    /// skipped and warned of: the entry count then differs from the table's, which is what the
    /// verification reports.
    pub fn entry_hashes(&self) -> Result<Vec<String>, String> {
        let AuditMirror::File { path } = self else { return Ok(Vec::new()) };
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read(path)
            .map_err(|cause| format!("The audit mirror at {} could not be read: {cause}", path.display()))?;
        let mut hashes = Vec::new();
        for line in String::from_utf8_lossy(&content).lines() {
            if line.chars().all(char::is_whitespace) {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => match value.get("entryHash") {
                    Some(serde_json::Value::String(hash)) if !hash.trim().is_empty() => hashes.push(hash.clone()),
                    Some(serde_json::Value::Number(number)) => hashes.push(number.to_string()),
                    _ => {}
                },
                Err(_) => tracing::warn!("A line of {} could not be read as an audit entry", path.display()),
            }
        }
        Ok(hashes)
    }
}

fn write_line(path: &std::path::Path, entry: &Entry) -> std::io::Result<()> {
    if let Some(parent) = std::path::absolute(path)?.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // One write call for the line and its terminator: two calls could interleave with another instance's
    // write and produce a line no parser can read — and a corrupted line in an integrity copy is
    // indistinguishable from tampering. `O_APPEND` makes each write land at the end, whoever else writes.
    let mut line = entry.to_json().into_bytes();
    line.push(b'\n');
    std::fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, hash: &str) -> Entry {
        Entry {
            id: id.to_owned(),
            timestamp: "2026-10-16T21:00:00.123456Z".to_owned(),
            operation: "login".to_owned(),
            resource_id: Some("1".to_owned()),
            user_id: None,
            ip_address: Some("203.0.113.9".to_owned()),
            user_agent: Some("curl/8 \"quoted\"\u{1f}".to_owned()),
            description: Some("line\nbreak é".to_owned()),
            previous_hash: None,
            entry_hash: hash.to_owned(),
        }
    }

    #[test]
    fn a_line_is_what_jackson_writes_for_the_record() {
        assert_eq!(
            entry("e1", "h1").to_json(),
            "{\"id\":\"e1\",\"timestamp\":\"2026-10-16T21:00:00.123456Z\",\"operation\":\"login\",\"resourceId\":\"1\",\
             \"userId\":null,\"ipAddress\":\"203.0.113.9\",\"userAgent\":\"curl/8 \\\"quoted\\\"\\u001F\",\
             \"description\":\"line\\nbreak é\",\"previousHash\":null,\"entryHash\":\"h1\"}"
        );
    }

    #[test]
    fn entries_are_appended_one_per_line_and_read_back_in_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("audit.ndjson");
        let mirror = AuditMirror::configured(Some(path.to_str().unwrap()));
        assert!(mirror.is_configured());
        assert_eq!(mirror.entry_hashes(), Ok(Vec::new()), "no file yet is no entries");
        assert!(mirror.append(&entry("e1", "h1")));
        assert!(mirror.append(&entry("e2", "h2")));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
        assert_eq!(mirror.entry_hashes(), Ok(vec!["h1".to_owned(), "h2".to_owned()]));
    }

    #[test]
    fn what_the_java_side_wrote_is_read_and_a_broken_line_costs_one_entry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.ndjson");
        std::fs::write(
            &path,
            "{\"id\":\"a\",\"entryHash\":\"java-1\"}\n\n   \n{broken\n{\"id\":\"b\",\"entryHash\":\"\"}\n{\"id\":\"c\",\"entryHash\":\"java-2\"}\n{\"id\":\"d\"}\n",
        )
        .unwrap();
        let mirror = AuditMirror::configured(Some(path.to_str().unwrap()));
        assert_eq!(mirror.entry_hashes(), Ok(vec!["java-1".to_owned(), "java-2".to_owned()]));
    }

    #[test]
    fn a_disabled_mirror_copies_nothing_and_fails_nothing() {
        for blank in [None, Some(""), Some("  \t")] {
            let mirror = AuditMirror::configured(blank);
            assert!(!mirror.is_configured());
            assert!(mirror.append(&entry("e", "h")));
            assert_eq!(mirror.entry_hashes(), Ok(Vec::new()));
        }
    }

    #[test]
    fn a_mirror_that_cannot_be_written_says_so_and_does_not_throw() {
        let directory = tempfile::tempdir().unwrap();
        // The path is a directory: opening it for append fails.
        let mirror = AuditMirror::configured(Some(directory.path().to_str().unwrap()));
        assert!(!mirror.append(&entry("e", "h")));
        assert!(mirror.entry_hashes().is_err(), "a directory is not a readable mirror");
    }
}
