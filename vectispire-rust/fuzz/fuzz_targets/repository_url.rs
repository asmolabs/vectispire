//! A repository URL is typed by anybody who may add a repository: every reader of one must answer,
//! never panic, and redaction must be stable — redacting twice gives what redacting once gave, or a
//! credential could survive the second pass that the first one exposed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_domain::repository_url;

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else { return };
    let _ = repository_url::validate(url);
    let _ = repository_url::is_https(url);
    let _ = repository_url::java_uri::parse(url);
    if let Some(host) = repository_url::host(url) {
        let _ = repository_url::has_host(url, &host);
        let _ = repository_url::normalize_host(&host);
    }
    let once = repository_url::redact(url);
    assert_eq!(repository_url::redact(&once), once, "redaction is not stable");
});
