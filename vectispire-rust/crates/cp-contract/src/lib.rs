//! **The control plane's contract, kept identical** — task 0.4 of the Rust port (plan §3.4, §4.3).
//!
//! The Angular client is generated from `openapi.json`, the agents call eight of its routes, and
//! customers' pipelines call the CLI and the gate against it: the document is what the port must not
//! change. This crate holds the Rust control plane to it, four ways.
//!
//! | | |
//! |---|---|
//! | [`check_routes`] | every route, method, parameter and security scheme the router *declares* against the document, both ways, with a ratcheted list of routes not ported yet |
//! | [`probe`] | the router itself, asked: each documented request is sent, and a route that was declared but not registered answers "no route" |
//! | [`Schemas`] | a body — a handler type serialized, a recorded answer, a replayed one — against the document's JSON Schema |
//! | [`replay`] | the recorded Java traffic, replayed against a server, key order and number text compared as Jackson wrote them |
//! | [`check_published`] | no operation id a release published is renamed or removed |
//!
//! The document and the published list are **embedded copies** of the Java line's (`reference/`,
//! moved by `reference/refresh.sh`), and the list of routes not ported yet is committed beside them:
//! each is something a check could otherwise be satisfied by editing.

mod axum_support;
mod document;
mod finding;
mod golden;
mod json;
mod published;
mod routes;
mod schema;

pub use axum_support::{AxumServer, HttpServer, NO_ROUTE_HEADER, RecordingRouter, probe};
pub use document::{
    Document, DocumentError, In, Media, Operation, Parameter, fill_parameters, path_parameters, split_parameter,
};
pub use finding::{Finding, assert_none, render};
pub use golden::{
    Body, Failure, FailureKind, Golden, LoadError, Normaliser, Replay, Report, Request, Response, Server, ServerError,
    load_dir, replay,
};
pub use json::{Compare, Difference, DifferenceKind, Json, MAX_DEPTH, Numbers, ParseError, compare};
pub use published::{Published, check_published};
pub use routes::{Allowlist, ParamDecl, RouteDecl, RouteSource, SecurityDecl, check_routes};
pub use schema::{Check, SchemaError, Schemas};

/// The conformance of a router that declares its routes as it registers them: the declarations
/// against the document and the published list, then the router against the document. Every finding
/// of every check, in one list.
pub async fn assert_router(
    router: &RecordingRouter,
    document: &Document,
    allowlist: &Allowlist,
    published: &Published,
) -> Vec<Finding> {
    let mut findings = check_routes(document, router, allowlist);
    findings.extend(check_published(document, published, Some(router)));
    findings.extend(probe(&router.router(), document, allowlist).await);
    findings
}
