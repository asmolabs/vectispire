//! The known-hosts file of the accept-new policy — what JGit's `OpenSshServerKeyDatabase` did for
//! `GitClone.AcceptNewDatabase`.
//!
//! **The file outlives the clone, and that is the whole point**: the first contact is recorded, a
//! changed key is refused. The predecessor of the Java class pointed this file at a directory created
//! per clone, so every clone was a first contact and nothing was ever refused.
//!
//! **A file this process cannot write is the operator's pin**, matched against and never added to: a
//! host it does not name is refused. Accept-new on it would accept a first contact and fail to record
//! it, so every clone would be a first contact again.
//!
//! Read as OpenSSH reads it: host patterns with `*`, `?` and `!`, `[host]:port` for another port,
//! hashed names (`|1|salt|hash`), `@revoked`. `@cert-authority` lines are not trusted — this agent does
//! not verify host certificates — and are skipped.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use std::io::Write;
use std::path::{Path, PathBuf};

/// What the file says about a host's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Listed with this key.
    Known,
    /// Listed, with other keys only — or with this one revoked.
    Changed,
    /// Not listed at all.
    Unknown,
}

/// The name a host is filed under: `host`, or `[host]:port` on another port than 22.
pub fn entry_name(host: &str, port: u16) -> String {
    let host = host.to_lowercase();
    if port == 22 { host } else { format!("[{host}]:{port}") }
}

/// What `file` says about `key` (`type` and raw blob) for `host` on `port`.
pub fn check(file: &Path, host: &str, port: u16, key_type: &str, key: &[u8]) -> Verdict {
    let Ok(content) = std::fs::read_to_string(file) else {
        return Verdict::Unknown;
    };
    let name = entry_name(host, port);
    let offered = STANDARD.encode(key);
    let mut listed = false;
    let mut matched = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut first = fields.next().unwrap_or_default();
        let revoked = first == "@revoked";
        if first.starts_with('@') {
            if !revoked {
                continue;
            }
            first = fields.next().unwrap_or_default();
        }
        let (Some(kind), Some(blob)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !hosts_match(first, &name) {
            continue;
        }
        let same_key = kind == key_type && blob == offered;
        if revoked {
            if same_key {
                return Verdict::Changed;
            }
            continue;
        }
        listed = true;
        matched |= same_key;
    }
    match (listed, matched) {
        (_, true) => Verdict::Known,
        (true, false) => Verdict::Changed,
        (false, false) => Verdict::Unknown,
    }
}

/// Records a first contact, in one write, as a line an operator can compare by eye: unhashed.
pub fn record(file: &Path, host: &str, port: u16, key_type: &str, key: &[u8]) -> std::io::Result<()> {
    let line = format!("{} {key_type} {}\n", entry_name(host, port), STANDARD.encode(key));
    let mut handle = std::fs::OpenOptions::new().append(true).create(true).open(file)?;
    handle.write_all(line.as_bytes())
}

/// Makes sure the file exists, whoever gets there first: two clones on a fresh machine both seeing no
/// file must not fail the second on "already exists".
pub fn prepare(file: &Path) -> std::io::Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::OpenOptions::new().write(true).create_new(true).open(file) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        // A read-only mount: the file is there and is the operator's.
        Err(_) if file.exists() => Ok(()),
        Err(error) => Err(error),
    }
}

/// Whether the file is the operator's pin — matched against, never added to.
///
/// **Read from the file's own bits as well as from an attempt to open it for writing**: root passes
/// any write check on an `r--r--r--` file, and an agent running as root would otherwise learn new
/// hosts into the operator's list.
pub fn is_pinned(file: &Path) -> bool {
    if std::fs::OpenOptions::new().append(true).open(file).is_err() {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(file).is_ok_and(|metadata| metadata.permissions().mode() & 0o200 == 0)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// OpenSSH's host list: comma-separated patterns, negated with `!`, or one hashed name.
fn hosts_match(patterns: &str, name: &str) -> bool {
    if let Some(hashed) = patterns.strip_prefix("|1|") {
        return hashed_matches(hashed, name);
    }
    let mut positive = false;
    for pattern in patterns.split(',') {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob(&negated.to_lowercase(), name) {
                return false;
            }
        } else if glob(&pattern.to_lowercase(), name) {
            positive = true;
        }
    }
    positive
}

fn hashed_matches(hashed: &str, name: &str) -> bool {
    let Some((salt, hash)) = hashed.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (STANDARD.decode(salt), STANDARD.decode(hash)) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(name.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// `*` and `?`, nothing else, as OpenSSH's `match_pattern`.
fn glob(pattern: &str, text: &str) -> bool {
    let (pattern, text): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(position) = star {
            p = position + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Where a policy's file lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostsFile(pub PathBuf);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_ports_negation_and_hashes_are_read_as_openssh_reads_them() {
        assert!(hosts_match("gitlab.example.org", "gitlab.example.org"));
        assert!(hosts_match("*.example.org,!evil.example.org", "gitlab.example.org"));
        assert!(!hosts_match("*.example.org,!evil.example.org", "evil.example.org"));
        assert!(hosts_match("[gitlab.example.org]:2222", &entry_name("GitLab.example.org", 2222)));
        assert!(!hosts_match("gitlab.example.org", &entry_name("gitlab.example.org", 2222)));
        // `ssh-keygen -H` of "gitlab.example.org" with a fixed salt.
        let salt = [7u8; 20];
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&salt).unwrap_or_else(|_| unreachable!());
        mac.update(b"gitlab.example.org");
        let hashed = format!("|1|{}|{}", STANDARD.encode(salt), STANDARD.encode(mac.finalize().into_bytes()));
        assert!(hosts_match(&hashed, "gitlab.example.org"));
        assert!(!hosts_match(&hashed, "other.example.org"));
    }

    #[test]
    fn a_listed_host_with_another_key_has_changed_and_a_revoked_key_is_refused() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let file = dir.path().join("known_hosts");
        record(&file, "gitlab.example.org", 22, "ssh-ed25519", b"first").unwrap_or_else(|_| unreachable!());
        assert_eq!(check(&file, "gitlab.example.org", 22, "ssh-ed25519", b"first"), Verdict::Known);
        assert_eq!(check(&file, "gitlab.example.org", 22, "ssh-ed25519", b"second"), Verdict::Changed);
        assert_eq!(check(&file, "gitlab.example.org", 2222, "ssh-ed25519", b"first"), Verdict::Unknown);
        std::fs::write(&file, format!("@revoked * ssh-ed25519 {}\n", STANDARD.encode(b"first")))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(check(&file, "gitlab.example.org", 22, "ssh-ed25519", b"first"), Verdict::Changed);
    }
}
