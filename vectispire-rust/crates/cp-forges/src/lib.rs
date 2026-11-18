//! Forges (decision 0037) — `core.forges`: read-only connections to GitHub and GitLab from which repositories are
//! discovered and imported as ordinary targets, and the change-review readings the checklists judge.
//!
//! **What it may use** (`cp-arch-tests/data/edges/forges.toml`, Java's `allowedDependencies`): `targets` for the
//! import, `checklists` for the change-review port this module implements, `access::security` for its routes. The
//! outbound door, the encryption and the audit log are the foundation's.

#![forbid(unsafe_code)]

mod persistence;
