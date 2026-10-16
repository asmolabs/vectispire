//! The control plane's HTTP stack — Phase 0, task 0.3 of the port plan.
//!
//! What this crate is, in one sentence: **Spring Security's filter chain as tower layers in the same order, the problem
//! documents and headers the Java server answers, and a route builder that does not compile without a role requirement
//! and a visibility handling.**
//!
//! | module | what it ports |
//! |---|---|
//! | [`chain`] | `SecurityConfiguration`'s chain: the layers, their order ([`chain::CHAIN`]), the CSP |
//! | [`access`] | the `@Requires*` markers and `authorizeHttpRequests`' rules |
//! | [`routes`] | the route builder (type-state), the route table, the 404 refusal |
//! | [`problem`] | `ProblemResponses` and `ProblemDetail`: two writers, two shapes, Jackson's escaping |
//! | [`address`] | `TrustedProxies` and `ClientBuckets` |
//! | [`buckets`] | the Bucket4j buckets of the limiters |
//! | [`limits`] | `RequestBodyLimitFilter` |
//! | [`routing`] | `routedPath`, the firewall and the container's refusals |
//! | [`extract`] | `JsonBody`, `Caller`, `Scoped<V>` — what a handler reads, refused in the Java sentences |
//! | [`interface`] | the Angular build, the SPA's deep links |
//! | [`credentials`] | the traits the chain is handed: sessions, keys, audit — Phase 1's |
//!
//! **Compared with the Java answers, not with a description of them:** `tests/golden/java/` holds what the
//! published 0.11.0-rc.3 control plane answered to the same requests, recorded by `tests/golden/capture.sh`, and
//! `tests/against_the_java_answers.rs` holds this crate to them.

#![forbid(unsafe_code)]

pub mod access;
pub mod address;
pub mod buckets;
pub mod chain;
pub mod credentials;
pub mod extract;
pub mod interface;
pub mod limits;
pub mod principal;
pub mod problem;
pub mod routes;
pub mod routing;

pub use access::Access;
pub use chain::{Chain, ChainConfig};
pub use extract::{Caller, ClientAddress, JsonBody, Scoped};
pub use principal::{ApiKeyScope, Principal, Role};
pub use problem::Problem;
pub use routes::{Route, Routes, require_visible};
