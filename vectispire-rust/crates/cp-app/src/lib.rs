//! The control plane's application, as a library so that its tests can reach what `main` wires: the registry
//! of routes, which `tests/route_authorization.rs` holds to the authorization rules of AGENTS.md, and the adapters
//! that join a module's seam to the runtime's implementation of it (`audit_mirror`), and the maintenance tasks every
//! module contributes (`maintenance`), the SIEM export's pieces (`siem`), which `tests/siem_composition.rs` exercises, which `tests/maintenance_composition.rs` holds to Java's composition.

#![forbid(unsafe_code)]

pub mod audit_mirror;
pub mod chain_entries;
pub mod ingestion;
pub mod maintenance;
pub mod registry;
pub mod siem;
pub mod startup;
pub mod worker;
