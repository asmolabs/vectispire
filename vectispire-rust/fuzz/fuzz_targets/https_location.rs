//! A `Location` header is the one thing an HTTPS forge says that the clone reads for itself, to name the
//! host a redirect was refused to: whatever the server sends, reading it must answer, never panic — and
//! the host it names never carries a path, a query or user info.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_domain::repository_url::java_uri;

fuzz_target!(|data: &[u8]| {
    let Ok(location) = std::str::from_utf8(data) else { return };
    if let Ok(parsed) = java_uri::parse(location.trim())
        && let Some(host) = parsed.host
    {
        assert!(!host.contains(['/', '?', '#', '@']), "the host carries more than a host");
    }
});
