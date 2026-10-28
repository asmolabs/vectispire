//! A failure report leaves the agent with whatever a tool or a server said, and what it carries is read by
//! people who must not find a secret in it: scrubbing must answer on any text, never panic and never grow
//! past its limit. (That a given secret is gone is pinned by `reference/failure-reason/`, not asserted here: the
//! rule removes each occurrence once, as the Java side does, so a text built around the secret can re-form it.)
//! The input is `raw`, a NUL, then the secret.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_protocol::failure_reason::{MAX_LENGTH, scrub};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (raw, secret) = text.split_once('\0').unwrap_or((text, ""));
    let scrubbed = scrub(raw, [Some(secret), None]);
    assert!(scrubbed.encode_utf16().count() <= MAX_LENGTH, "the reason outgrew its limit");
});
