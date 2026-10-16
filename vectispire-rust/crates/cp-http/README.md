# vectispire-cp-http

The control plane's HTTP stack — **Phase 0, task 0.3** of the port plan
(`docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md`, §7). Not shipped: the Java control plane is the product.

Spring Security's filter chain as **tower layers in the same order**, the problem documents and headers the Java server
answers, and a route builder that **does not compile** without a role requirement and a visibility handling.

## The chain

```text
request ─▶ firewall ─▶ client-address ─▶ headers ─▶ login-limit ─▶ webhook-limit ─▶ body-limit
        ─▶ bearer-limit ─▶ bearer ─▶ access ─▶ problems ─▶ router
                                                             └▶ per route: password-change ─▶ credential-confinement ─▶ role ─▶ handler
```

`chain::CHAIN` names them; `tests/chain_order.rs` drives a request through all thirteen and compares the order they ran in.
Why each position matters is written beside the layer in `src/chain.rs` (the Java reasoning, carried over).

## The route builder

```rust
Route::get("/api/v1/repositories")   // RouteSpec<Unset, Unset>
    .requires(Access::Account)       // which @Requires* marker
    .scoped()                        // or .names_no_target(): how the route handles visibility
    .accepts_api_key(ApiKeyScope::Read)   // optional, opt-in: a key reaches only routes that say so
    .handler(list)                   // exists only once both questions are answered
```

`tests/ui/*.rs` are compile-fail cases (`trybuild`): a route with no marker, with no visibility, with neither, with a
marker twice, scoped *and* naming no target — each is refused by the compiler, and its message is the expected output.
`Routes::table()` lists every route and what it declared: the input of the ports of `AuthorizationCoverageTest` and
`RouteAuthorizationTest`, which are Phase 1's. `require_visible` is the refusal a scoped handler owes: **a 404, never a 403,
and the same bytes for an absent row and a hidden one**.

## What it is held to

`tests/golden/java/` holds what the **published 0.11.0-rc.3 control plane answered** to 72 requests — recorded on a
throwaway MySQL by `tests/golden/capture.sh` (re-run it on purpose, never to make a test pass) — and
`tests/against_the_java_answers.rs` compares status, every header but the framing ones, and the body. Beyond them: 110 tests
on the layers, the limiters (asserted through the chain that ships, as `BearerThrottleWiringTest` does), the markers against
every role, and the credential kinds against the routes that do and do not accept them. Each guard was broken in turn
and a test turned red (see the report of the commit that added this crate).

**Where it differs, on purpose:**

* `Content-Length` / `Transfer-Encoding`: the server frames its answers (Tomcat there, hyper here); the Java side sends a
  chunked body for a handler's problem and a length for the chain's. The body bytes are what a client reads.
* `Allow`: the order of the methods (Spring lists `POST, GET`; this crate sorts). Compared as a set.
* A `Range` request for the forwarded `index.html` is answered whole; the build's other files are served by `tower-http`,
  which honours it.
* The Java server's container-level 400 for a request target it cannot parse (a raw `\`) carries no `instance`; reproduced.
* `Content-Language: en-US` on a forwarded page is the Java container's default locale, pinned (`interface::CONTENT_LANGUAGE`).

## What it does not do

Nothing here reads a table. A session's hash, an API key, the SCIM token, the audit log and the visibility resolver are
`Credentials`, `Audit`, `SharedWindow` and `VisibilityOf<V>` — traits Phase 1 (`cp-access`, `cp-audit`) implements; the
doubles in `credentials.rs` are what its tests start from. The actuator endpoints themselves are `cp-runtime`'s (0.6): this
crate only decides who may reach them.

## Isolation

`deny.toml` lets only this crate link `axum` (`wrappers`), and `crates/agent/tests/isolation.rs` proves the agent's graph
does not. `unsafe` is forbidden here, with no exception.
