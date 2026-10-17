//! The control plane's application, as a library so that its tests can reach what `main` wires: the registry
//! of routes, which `tests/route_authorization.rs` holds to the authorization rules of AGENTS.md, and the adapters
//! that join a module's seam to the runtime's implementation of it (`audit_mirror`).

#![forbid(unsafe_code)]

pub mod audit_mirror;
pub mod registry;
