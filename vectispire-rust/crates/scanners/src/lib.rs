//! The scanners the agent runs, and the parsers that read what they write.
//!
//! **A parser here is a data contract, not plumbing.** The agent sends parsed findings, and their rule
//! id, type and path enter the issue fingerprint: a path normalised one character differently from
//! the Java parser resolves every existing issue and recreates it, its triage lost, across every
//! target (AGENTS.md, "Four traps"). Each parser is therefore held to the Java side's answers for a
//! fixed set of scanner outputs — `reference/<scanner>/` — and a difference fails the build on both
//! sides (see `README.md`, "The reference sets").
//!
//! [`jackson`] reproduces the leniencies of the Java parsers' JSON reading, which the findings
//! depend on: what a number in a text field becomes, what a text in a number field becomes.

pub mod container_paths;
pub mod failure;
pub mod images;
pub mod jackson;
pub mod secrets;
