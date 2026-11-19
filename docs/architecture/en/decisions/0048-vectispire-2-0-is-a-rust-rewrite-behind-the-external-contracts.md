# 0048 — Vectispire 2.0.0 is a Rust rewrite behind the external contracts, not a port

**Date:** 2026-11-19 · **Status:** proposed · **Builds on:** [0003](0003-long-polling-for-agents.md), [0007](0007-none-is-not-an-empty-list.md), [0024](0024-integration-api-keys-act-for-an-account.md), [0043](0043-what-1-0-promises.md), [0045](0045-on-a-cluster-without-docker-agents-run-each-scanner-as-a-pod.md) · **Decider:** Laurent Boucher

## Context

On 2026-10-16 the product owner asked for "a Rust port" of Vectispire: the agent first, then the whole control
plane. The word was taken literally. The control plane's port (`vectispire-rust/crates/cp-*`) reproduces the Java
application **behaviour for behaviour**: every one of the 322 operations of `openapi.json`, the same schema under the
same Flyway history, and the same bytes on the wire — Spring's error sentences, Jackson's reading of a missing field,
`BigDecimal`'s rounding, `URLDecoder`'s decoding, Java's `HashMap` iteration order where a response exposes it. Parity
is proved by recording the Java suite's HTTP traffic and replaying it against the Rust binary (`cp-contract`,
`golden/`): about an hour per full run, with recordings that cannot replay at all (Mockito stand-ins, fake servers on
the loopback) or that depend on timing (a per-minute rate window).

By 2026-11-19 the port served roughly 250 of the 322 operations, at a cost the product owner had not anticipated, and
on that day said what had been meant: **a rewrite in Rust, written as Rust, not a port**. The same day the
control-plane port was paused and all Rust effort moved to the agent.

Three findings of the port shape this decision:

- **Most of its effort buys parity, not product.** A large share of each module is reproducing the framework's
  incidental behaviour so the replay stays green. That work has no value once Java is retired.
- **The security gain of the control plane in Rust is modest.** Java is memory-safe already. Rust removes classes of
  flaw that live in the JVM's ecosystem — deserialisation gadgets, reflective binding, expression languages, JNDI
  lookups — and shrinks the image and the dependency tree. But the control plane's real risks are logic: the four traps
  of `AGENTS.md`, the routes that served other accounts' data, the refusal that confirmed an existence. Those are kept
  by rules and tests, in either language.
- **The agent is where Rust pays most.** It runs on customers' machines, parses untrusted repository content and
  scanner output, and talks to the control plane through a contract that is already external (0003, 0043 §2). Its
  port is a good port: the protocol must stay identical anyway.

## Decision

1. **The agent continues as a port and ships first.** Its streams (workspace census and API discovery, plugins and
   cosign verification, the Kubernetes executor of 0045, then a reproducible image and two weeks of identical results
   beside the Java agent in the nightly) are unchanged. It depends only on the agent protocol, so it serves a 1.x
   control plane and a 2.0 one alike.

2. **The control plane of 2.0 is a rewrite.** It is designed and written as Rust — types that make illegal states
   unrepresentable, errors as values, explicit transactions, no reproduction of Spring's or Jackson's incidental
   behaviour. **It owes parity with 1.x only on the external contracts listed in point 3.** Everything else — internal
   routes, response shapes the interface alone reads, the schema, the module boundaries — is redesigned.

3. **The external contracts are the boundary, and they are listed.** A 1.x installation's integrations, agents and
   evidence must keep working, unchanged, against 2.0:

   | Contract | Today | What "unchanged" means |
   |---|---|---|
   | Agent protocol | `/api/v1/agent/*` (9 routes), `AgentContract` `OLDEST_SERVED`–`CURRENT` | a 1.x agent of the previous minor claims, scans and reports against 2.0 (the `previous-agent` CI job) |
   | Integration API | the 47 routes marked `@AcceptsApiKey` (0024): the gate, SARIF and report imports, scans, issues, inventory, compliance, exports, CycloneDX, VEX, CSAF, the AI advisor | same paths, methods, parameters, response fields and status codes; an integration key issued by 1.x still works |
   | Inbound webhooks | the trackers' webhook (`/api/v1/tickets/webhook/{provider}`) | same verification of the provider's signature, same effects |
   | Identity | SCIM 2.0 provisioning, OIDC sign-in | a configured identity provider keeps provisioning and signing in |
   | Outbound formats | SIEM (CEF over syslog and webhook), notification webhooks and their signature, tracker issues | a collector, a receiver or a tracker sees the same messages |
   | Plugin contracts | scanner plugins emitting SARIF (0017), report plugins | a plugin image built for 1.x runs under 2.0 |
   | Documents | SARIF, CycloneDX (0016), VEX, CSAF, signed checklist documents, the audit export | a document 1.x produced still verifies; a document 2.0 produces is read by the same tools |
   | CI templates | `ci/gitlab/vectispire-gate.gitlab-ci.yml` and its peers | a pipeline using the template needs no change |
   | Operations | the configuration an operator sets (environment variables, properties), the Prometheus scrape | a 1.x configuration starts 2.0, or 2.0 refuses it at start naming each key to change — never a silent default |

   Each row gets a **contract test suite** written before the code that serves it, run against 1.x first (it must
   pass there) and then against 2.0. The Java traffic recorder may still produce these suites' fixtures, for the
   external routes only.

4. **The web interface stays Angular** (decided by the product owner on 2026-11-19). It moves to the redesigned
   internal API in the same releases as the back end. The screens are reworked for that API anyway, but changing how
   they are built at the same time would add a second migration — the design system, the two languages, the
   Playwright suite, the team's own skills — to the one the back end and its data already are. A Rust interface was
   weighed and set aside (see "Alternatives considered"); the HTTP boundary keeps the question open for a later major.

5. **The data moves once, forward, rehearsed.** 2.0 has its own schema, on MySQL only (as 1.0, decision 0043 §3). A
   migration tool reads a 1.x database (the last 1.x migration, today V102) and writes a 2.0 one; the 1.x database is
   left untouched, so rolling back is pointing 1.x at it again. Before any installation switches, the tool runs on a
   copy of that installation's data and a check compares, at least:
   - **counts** of every kind of record;
   - **issue fingerprints**, identical — a changed fingerprint resolves the issue and loses its triage, silently;
   - **triage and its history**, exceptions and their expiries;
   - **the audit log's chain**, still verifiable end to end — the 1.x entries keep their hashes, and the first 2.0
     entry chains onto the last 1.x one;
   - **sealed secrets** (deploy keys, tokens, signing keys), readable under the same `ENCRYPTION_KEY` and contexts, or
     re-sealed and counted by the encryption census;
   - **identifiers that left the product** — issue ids in tracker links and exported documents, scan ids in SARIF —
     kept, or mapped with the mapping published.

6. **The lessons of 1.x carry over as code, not as memory.** Each trap of `AGENTS.md` and each executable rule of
   the 1.x architecture tests is restated for 2.0 as a type, a crate boundary or a test, before the module it governs
   is written: visibility applied in the query and a refusal answered 404, never 403; absent is not empty (0007); the
   fingerprint as a data contract; the agent holding no database connection (0003); every outbound call through the
   guard; a wiring proved on a started binary.

7. **The work already done is sorted crate by crate, not discarded.** At this decision the workspace holds about
   183,000 lines of Rust (`vectispire-rust/crates/`, sources only), in five groups:

   | Group | Crates | Lines | In 2.0 |
   |---|---|---|---|
   | The agent and what it shares | `agent`, `scanners`, `container`, `runner`, `protocol`, `crypto`, `tls`, `git`, `testkit`, `domain` | ~25,700 | **kept as is** — the agent ships from them (point 1); `domain`'s Java-compatibility helpers (`java`, `wire`) stay for the protocol's sake |
   | The agent protocol's server side | `cp-agents` | ~4,000 | **kept, closest to its current form**: the protocol is an external contract, so its behaviour is the one place where parity with 1.x remains the rule |
   | Foundations | `cp-outbound` (the guard and the pinned sender), `cp-crypto` (sealing under 1.x's contexts), `cp-audit` (the hash chain), `cp-db`, `cp-http`, `cp-outbox`, `cp-maintenance`, `cp-runtime`, `cp-settings`, `cp-arch-tests` | ~23,600 | **kept and adapted**: the guard, the sealing and the chain are needed unchanged for the migration (point 5); the request chain, the configuration and the architecture rules are reshaped to 2.0's design |
   | Domain modules | `cp-access`, `cp-checklists`, `cp-scanning`, `cp-issues`, `cp-targets`, `cp-forges`, `cp-inventory`, `cp-compliance`, `cp-posture`, `cp-threatintel`, `cp-gate`, `cp-tickets`, `cp-rules`, `cp-siem`, `cp-notifications`, `cp-ai`, `cp-platform`, `cp-app` | ~122,000 | **the source the rewrite starts from, not its result**: the rules they encode (visibility, triage, the gate's verdict, the KEV and EPSS feeds, the sync of findings into issues) are carried into 2.0's modules with their tests; the parity layers around them — Spring's coercion messages, Jackson's readings, the response shapes only the interface reads — are dropped |
   | Parity tooling | `cp-contract` (the replay of the Java suite), `migrate` (Flyway's history reproduced) | ~9,400 | **narrowed**: `cp-contract` keeps the contract checks of the external routes (point 3) and drops the whole-suite replay; `migrate` becomes the reader of a 1.x schema for the migration tool (point 5) |

   The Java side's pieces written for the port follow the same sort: the reference sets of the agent's scanners and
   of the protocol stay; the traffic recorder records the external routes only.

8. **1.x stays the maintained product until 2.0 passes the drill.** New features land in 1.x only when they cannot
   wait; a module already rewritten for 2.0 gets its 1.x fixes ported by the change that makes them. 2.0 is released
   only after the migration drill on a production copy and a period side by side on staging, as decided for the
   switch-over on 2026-10-28.

## Consequences

- The cost of 2.0 is the cost of the product, not of matching Java's incidental behaviour; it is still a large
  project, to be estimated by the spike of the open questions before the rewrite starts.
- The contract suites become the product's most important tests: what they do not cover is free to change, so a
  contract they omit can be broken without anyone noticing. Writing them is the first deliverable.
- Running 1.x and 2.0 side by side means two codebases for a while; point 8 bounds that window, and it is the riskiest
  part of the plan (a fix that lands in one only).
- Of the ~183,000 lines already written, the agent side (~26,000) and the protocol's server side are kept; the
  foundations (~24,000) are adapted; the domain modules (~122,000) become the source of the rewrite rather than its
  result; the parity tooling (~9,000) is narrowed to the external contracts.

## Alternatives considered

- **Continue the port to full parity, then evolve in Rust.** Rejected: it pays for parity twice — once to reach it,
  once to undo it — and the recorded oracle cannot cover what the Java suite never exercised.
- **Stop Rust for the control plane and keep Java.** Remains a valid outcome: if the spike shows the rewrite is not
  worth its cost, 2.0 keeps the Java control plane and the Rust agent. This decision does not pre-empt that answer;
  it fixes how a rewrite is done if one is done.
- **A Rust interface.** Two shapes were compared:

  | | Axum + Askama + htmx | Leptos |
  |---|---|---|
  | Shape | HTML rendered by the server, fragments swapped by htmx; almost no JavaScript | a single-page application compiled to WebAssembly, rendered on the server and hydrated |
  | For | no npm supply chain in production; one toolchain and one deliverable; authorisation decided once, on the server; a strict CSP is easy; templates checked at compile time; the Playwright suite largely survives | the closest to today's interface; fine-grained reactivity; server functions shared with Axum |
  | Against | rich charts and highly interactive screens still need some JavaScript or SVG drawn on the server; the design system and the two languages are rebuilt | pre-1.0 and its API moves; a WebAssembly bundle and its toolchain to ship and audit; a single-page application's complexity for little more than one language |

  Dioxus's strength — one code base for web, desktop and mobile — does not apply to a web-only product; Yew has
  slowed, Sycamore's community is small, and native or immediate-mode toolkits (egui, Iced, Slint) do not make an
  accessible, bilingual web application. Server-rendered HTML was the stronger of the two, chiefly for removing the npm
  supply chain; it was set aside on 2026-11-19 to keep 2.0 to one migration, and is the candidate to weigh first if a
  later major reopens the question.

## Open questions, to settle before the rewrite starts

1. **A spike**: one vertical slice — issues, triage and the gate, with their external routes and the migration of
   their data — rewritten end to end, its contract suite passing on 1.x and 2.0, to measure the real cost per module.
2. **The configuration**: which 1.x keys 2.0 accepts as they are, which it renames, and how it says so.
3. **Identifiers**: whether 2.0 keeps 1.x's numeric ids or maps them, given the links trackers and documents hold.
4. **The audit chain across the migration**: the exact form of the bridge between the last 1.x entry and the first
   2.0 one, and how a verifier reads both.
5. **The repository**: whether the 2.0 control plane lives in this repository or in a new one. A new one gives it a
   history, a pipeline and a roadmap of its own, which suits a rewrite. But the agent depends on this repository today
   — its reference sets are written by the Java tests, its conformance and the `previous-agent` job run beside the Java
   agent — and the release signatures name this repository's workflow, so a new repository is a new signing identity
   for consumers to learn. If it is chosen, the move comes after the agent ships from here and once the external
   contract suites (point 3) are published from this repository as a versioned artifact the new one consumes.
