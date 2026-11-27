//! The archive a daemon saved for an image is read before anything else touches it — its tar headers, its
//! `manifest.json`, the configurations that names. Any bytes must be answered, never a panic: a file, an absence,
//! or why the archive cannot be read. And whatever the bytes, the check answers either nothing (every image of the
//! platform asked) or a sentence: a refusal, never a scan of something unchecked.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vectispire_container::image_archive::{self, CONFIG_LIMIT, MANIFEST_LIMIT, Platform};

fuzz_target!(|data: &[u8]| {
    let _ = image_archive::entry_of(Cursor::new(data), "manifest.json", MANIFEST_LIMIT);
    let _ = image_archive::entry_of(Cursor::new(data), "./blobs/sha256/x", 16);
    let _ = image_archive::number(data);

    let asked = Platform::of("linux", "amd64", "");
    let refusal = image_archive::refusal("image", "linux/amd64", &asked, |name, limit| {
        image_archive::entry_of(Cursor::new(data), name, limit.min(CONFIG_LIMIT))
    });
    if let Some(refusal) = refusal {
        assert!(!refusal.is_empty());
    }

    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(Some(platform)) = image_archive::requested(text) {
            // What is sent the daemon is the JSON of an OCI platform, whatever was configured.
            let query: serde_json::Value = serde_json::from_str(&platform.save_query()).expect("the query is JSON");
            assert!(query.get("os").is_some() && query.get("architecture").is_some());
            assert!(platform.admits(&platform), "a platform admits itself");
        }
    }
});
