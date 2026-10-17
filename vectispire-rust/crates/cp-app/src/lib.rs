//! The control plane's application, as a library so that its tests can reach what `main` wires: the registry
//! of routes, which `tests/route_authorization.rs` holds to the authorization rules of AGENTS.md.

#![forbid(unsafe_code)]

pub mod registry;
