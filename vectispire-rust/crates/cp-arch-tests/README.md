# vectispire-cp-arch-tests

The boundaries of the Rust control plane, as tests — written **before** the first module crate, because a
boundary added after the code has crossed it is a refactoring and not a rule. Phase 0, task 0.8 of
the port's plan (`docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md`, on the `docs/rust-control-plane-plan` branch: §2, §6.1, §7).

| rule | where | Java |
|---|---|---|
| A crate depends only on what `data/edges.toml` allows; no cycle; the pure crates stay pure; nothing the agent links is control-plane code | `src/edges.rs`, `src/graph.rs` | `ModularityTest`, `domainIsPure`, `configSitsUnderEveryModule` |
| The layers inside a module crate; the places are closed; `web`, `internal`, `persistence` are not `pub` | `src/layering.rs`, `src/facts.rs` | `ArchitectureTest` |
| A statement naming another module's table is on a list that only shrinks | `src/sql.rs` | `CrossModuleQueriesTest` |
| `unsafe` is forbidden, with one named exception | `src/unsafe_code.rs` | — |
| The agent links no control-plane code and never names the encryption key | `src/isolation.rs` | `AgentIsolationTest` |
| Every route declares who may call it and settles whose data it serves | `src/routes.rs` | `RouteAuthorizationTest`, `AuthorizationCoverageTest` |

## What is data, and what a change to it means

- **`data/edges.toml`** — the twenty-eight modules and their `allowedDependencies`, read from the Java `package-info.java`
  files on the 0.11.1 line (b8bd7e8d0), with the infrastructure crates (`db`, `http`, `contract`, `runtime`, `app`). **A
  line in it is a decision for the review.** A new module crate is a line here first (`status = "pending"`); when its
  port is finished it becomes `"ported"`, and from then on a listed edge its crate does not use fails (Modulith's "a line
  nothing uses"). `platform` is `open`: the shell composes several domains, and the port writes its list when it lands.
- **`data/tables.toml`** — which module owns which of the 77 tables, read from the JPA entities. A table is a line in the
  module that owns it.
- **`data/sql-known.toml`** — the statements that cross, with their reasons. The list only shrinks; a ported module's
  entry fails the day its statement stops naming the table.
- **`data/anonymous-routes.txt`** — the seven routes open to anonymous callers, each with a reason; the list is exact.

`cargo test -p vectispire-cp-arch-tests --test workspace -- --nocapture` prints the order the port goes in: each
module after everything it may use (`access → targets → scanning → …`).

## How it proves itself

Every rule is run on a **synthetic workspace** built to be clean (`tests/common/mod.rs`: path-only crates, stand-ins for
`sqlx` and `axum` outside the workspace directory so that they are not members), then broken one way at a time. A rule that
has never failed has never been shown to fail. The tests over the **real** workspace (`tests/workspace.rs`) report how
much they read and assert a floor, so that a rule pointed at nothing cannot say green.

Today the workspace holds the agent and no module crate, so the rules that need module crates are silent on it by
necessity; the rules about what exists — the agent's isolation, `unsafe`, the pure crates, the edge list's own
consistency — are live.

## When a module crate lands

Add the crate as `crates/cp-<module>/` (package `vectispire-cp-<module>`) with the layout the rules read —
`src/lib.rs` (API, `#![forbid(unsafe_code)]`), `src/web/`, `src/internal/`, `src/persistence/`, plus a directory for each
named interface — declare `mod web; mod internal; mod persistence;` **without** `pub`, and let `lib.rs` forward its routes
(`pub fn routes() { web::routes() }`): the root file is the one place allowed to name `web`.

## Not done here, and who does it

- **Route coverage over the real router.** `routes.rs` defines the descriptor it needs (`RouteDescriptor`) and the
  checks, proven on descriptors written by hand. `cp-http`'s builder will expose its registry, and the adapter from that
  type to `RouteDescriptor` lives with `cp-app`'s tests, which depends on both; this crate depends on neither.
- **The pool crate's query vocabulary.** `layering::QUERY_API` names `sqlx` and `sea-query`; when `cp-db`'s module layout
  lands, its paths that build a query are a line there, and its paging vocabulary stays allowed to a service.
- **The agent's own isolation test** walks every source under `crates/` for the key's name. Once a control-plane crate
  names the key (it will: it holds it), that walk must narrow to the crates the agent links, as `src/isolation.rs` already
  does.
