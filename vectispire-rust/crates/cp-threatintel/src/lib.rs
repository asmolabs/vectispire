//! Threat intelligence — Java's `core/threatintel`: the CISA KEV catalogue and FIRST's EPSS file, each read whole or
//! not at all, the backlog's exploitation re-evaluated against them, and the ranking of the open vulnerabilities.
//!
//! **The pure decisions are this crate's root files, not `vectispire-domain`'s**: the agent links that crate, and
//! nothing here is the agent's — the reader of the EPSS file links zlib besides. They are held to
//! `reference/threatintel/`, which `ThreatIntelReferenceSetTest` writes from the Java classes.

#![forbid(unsafe_code)]

pub mod epss_file;
pub mod feeds;
pub mod kev_catalog;
mod persistence;
pub mod risk_matrix;
pub mod status;
