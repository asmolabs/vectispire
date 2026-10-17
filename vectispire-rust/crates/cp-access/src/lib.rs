//! The control plane's `access` module — who a request is, and what it may see.
//!
//! Ported in Phase 1 of the control plane's port (docs/analysis/…_rust_control_plane_port_plan, §7): this crate holds
//! **the credentials** so far (task 1.2). Accounts and passwords (1.1), MFA and throttles (1.3), single sign-on
//! (1.4), roles and visibility (1.5) and the routes (1.7) land beside them. The layout is the module's four places
//! (`cp-arch-tests`, `layering.rs`): the root is the API, `internal` the implementation, `persistence` every query.

#![forbid(unsafe_code)]

mod internal;
mod persistence;

pub mod credentials;
