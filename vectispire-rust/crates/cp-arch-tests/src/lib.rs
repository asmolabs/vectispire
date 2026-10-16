//! The boundaries of the Rust control plane, as tests.
//!
//! The Java control plane keeps its architecture with tools that read the compiled classes: ArchUnit
//! (`ArchitectureTest`), Spring Modulith (`ModularityTest`), and four tests that read text and the registered
//! routes (`CrossModuleQueriesTest`, `AuthorizationCoverageTest`, `RouteAuthorizationTest`,
//! `MigrationLayoutTest`). Rust has no ArchUnit, and the boundaries must exist before the first module does,
//! because a boundary added after the code has crossed it is a refactoring and not a rule. Each file here is one
//! of those rules, written as a library of checks that take a model of the workspace and return violations — so
//! that the same function runs over the real workspace and over the synthetic ones the tests build to prove it
//! bites (`tests/`).
//!
//! | file | rule | Java |
//! |---|---|---|
//! | `edges.rs` | a crate depends only on what `data/edges.toml` allows; no cycle; the pure crates stay pure; nothing the agent links is control-plane code | `ModularityTest`, `domainIsPure`, `configSitsUnderEveryModule` |
//! | `layering.rs` | the layers inside a module crate; the places are closed | `ArchitectureTest` |
//! | `sql.rs` | a statement naming another module's table is on a list that only shrinks | `CrossModuleQueriesTest` |
//! | `unsafe_code.rs` | `unsafe` is forbidden, with one named exception | — (the JVM has none) |
//! | `isolation.rs` | the agent links no control-plane code and never names the encryption key | `AgentIsolationTest` |
//! | `routes.rs` | every route declares who may call it and settles whose data it serves | `RouteAuthorizationTest`, `AuthorizationCoverageTest` |
//!
//! **A green result says what it read.** Every check returns, or is paired with, a count of the crates, files and
//! paths it examined, and the tests assert a floor: a rule that read nothing is the failure mode these checks
//! exist to prevent (the secrets scan that examined zero commits, for six weeks, and said so in green).

#![forbid(unsafe_code)]

pub mod edges;
pub mod facts;
pub mod graph;
pub mod isolation;
pub mod layering;
pub mod model;
pub mod routes;
pub mod source;
pub mod sql;
pub mod unsafe_code;
