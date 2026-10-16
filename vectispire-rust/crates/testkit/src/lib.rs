//! Test support: the reference sets the port is held to, and throwaway containers.
//!
//! **Only ever a dev-dependency.** `crates/agent/tests/isolation.rs` refuses it in the agent's
//! normal dependency graph, like the database crates.

#![allow(clippy::unwrap_used, clippy::expect_used)] // A test helper fails the test, which is the point.

pub mod docker;
pub mod forge;
pub mod proxy;

use std::path::PathBuf;

/// `vectispire-rust/reference/`, wherever the workspace is checked out.
pub fn reference_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference")
}

/// A file of the reference set, as text.
pub fn read(relative: &str) -> String {
    let path = reference_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A file of the reference set, as JSON.
pub fn read_json(relative: &str) -> serde_json::Value {
    serde_json::from_str(&read(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

/// What the Rust side writes into the reference set — files the Java side reads back
/// (`crypto/rust-vectors.json`). Written with `VECTISPIRE_REFERENCE_WRITE=1`, otherwise required to
/// be exactly what is committed, so a change on this side is red until the file — and therefore the
/// Java check that reads it — has followed.
pub fn expect(relative: &str, content: &str) {
    let path = reference_root().join(relative);
    if std::env::var("VECTISPIRE_REFERENCE_WRITE").is_ok_and(|value| value == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == content,
        "{relative} differs from what the Rust side writes. Regenerate it with VECTISPIRE_REFERENCE_WRITE=1 cargo test, \
         then run the Java side's *ReferenceSetTest so that it reads the new file."
    );
}
