//! A known-hosts file may be an operator's, edited by hand: checking a key against any content must
//! answer, never panic — and a key just recorded for a valid host must then be known, whatever the
//! file already held for others.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;
use vectispire_domain::repository_url;
use vectispire_git::known_hosts::{self, Verdict};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (host, content) = text.split_once('\n').unwrap_or((text, ""));
    let Ok(mut file) = tempfile::NamedTempFile::new() else { return };
    if file.write_all(content.as_bytes()).is_err() {
        return;
    }
    let key = b"fuzzed-key-blob";
    let _ = known_hosts::check(file.path(), host, 22, "ssh-ed25519", key);
    let _ = known_hosts::is_pinned(file.path());

    // Only a host the URL checks would let through reaches a clone, so only one is held to the
    // round trip; and a file that already lists this host is allowed to answer `Changed`.
    let Ok(host) = repository_url::normalize_host(host) else { return };
    let Ok(fresh) = tempfile::NamedTempFile::new() else { return };
    if known_hosts::record(fresh.path(), &host, 2222, "ssh-ed25519", key).is_err() {
        return;
    }
    assert!(
        matches!(known_hosts::check(fresh.path(), &host, 2222, "ssh-ed25519", key), Verdict::Known),
        "a key recorded for {host:?} is not known afterwards"
    );
});
