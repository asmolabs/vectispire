# vectispire-rust — the remote agent and the control plane's foundations, in Rust

**Port in progress, not shipped.** Nothing here is built by `release.yml` or published, and no
deployment runs it. The agent that ships is `vectispire-java/vectispire-agent`. This binary speaks the
whole agent protocol — it announces itself and its signed sealing key, claims up to its limit of scans
at once, opens the credentials they carry, beats for each, and hands back a signed result or a signed,
scrubbed failure report — and it runs a repository scan: the clone and the four analyses
(dependencies, secrets, IaC, SAST), as the Java agent does (`crates/agent/src/scan.rs`). **What is not
ported yet is said, never read as "found nothing"**: the API discovery is recorded as a step that did
not run, a plugin as an absent step under its name, and an image target goes back to the queue as a
transient failure for an agent that can export images. Never point it at a control plane whose scans
matter.

The costed study behind the port is on branch `docs/rust-agent-study`
(`docs/analysis/en/2026-10-16_rust_agent_port_study.en.md`). This directory is its Phase 0, built as
the foundation the rest of the port extends rather than as a throwaway spike.

```sh
./check.sh     # fmt, clippy -D warnings, every test (Docker required), cargo deny, then the
               # security checks: unsafe, lint ceilings, cargo vet, semgrep (security/README.md)
./measure.sh   # image size, idle memory, Grype — GRYPE_DIGEST=<the digest ScannerImages pins>
```

The toolchain is pinned by `rust-toolchain.toml`.

## Layout

| Crate | Owns | Java counterpart |
|---|---|---|
| `agent` | the binary: configuration (same variables as the Java agent, and the secrets read from the `configtree:` it names, as the composition passes them), logging, `check docker` / `check clone`, the loop (`serve.rs`: slots, heartbeats, a lost lease, the graceful stop) and the scan runner (`scan.rs`: workspace, clone, sub-path, the steps, rule placement) | `vectispire-agent` (`AgentRunner`, `AgentLoop`, `Slots`) |
| `protocol` | every agent route and its bodies (`ScanTask` in, `ScanArtifacts` out), the HTTP client of the control plane, the opening of sealed credentials, the failure reason's scrub, the concurrency limit | `AgentProtocol`, `AgentHttp`, `ScanTask`, `ScanArtifacts`, `FailureReason`, `AgentConcurrency` |
| `crypto` | result, failure and sealing-key signatures; sealed envelopes | `domain.crypto` |
| `git` | the clone: SSH (libgit2 and libssh2, host keys pinned or recorded), HTTPS (this crate's own smart-HTTP transport on rustls), failure kinds and sentences | `GitClone`, `RedirectRefusingConnections`, `CloneFailureException` |
| `container` | scanner containers through the Docker API or the socket proxy, in one closed shape | `ContainerRunner`, `ContainerRun`, `ScannerLimits` |
| `scanners` | each scanner's run and the parser of its output (secrets today) | `scanning.scanners` |
| `domain` | repository-URL checks (a port of `java.net.URI`'s parser), metadata addresses, failure kinds, the contract number, `Secret` | `RepositoryUrl`, `LinkLocalHosts`, `FailureKind`, `AgentContract` |
| `tls` | the one trust every HTTPS connection uses | the JVM truststore |
| `testkit` | test support only: the reference sets, throwaway containers, the test forge and the stub control plane (`control_plane.rs`, on a loopback port, one thread per connection) | — |

**The agent's isolation is a property of the graph** (decision 0003). The agent and the control plane's crates
(`cp-*`, `migrate`, below) share only the pure crates — `domain` (with the Jackson-compatible writer, `wire`),
`crypto`, `git` and `tls`; no `cp-*` crate is reachable from the agent. `crates/agent/tests/isolation.rs` reads
`cargo metadata` and fails if the agent links any database client, server framework or test-support crate.
`deny.toml` bans the same crates outside the control plane's crates (the `wrappers` of its `sqlx` and `axum`
bans name exactly who may use them), and `cp-arch-tests` asserts the same from the workspace side. A second
test fails if any source outside `crates/cp-*` names the control plane's encryption key.

## Conventions

These are what the rest of the port follows.

- **Errors.** `thiserror`, one enum or struct per crate. A message an operator reads is the Java side's
  sentence, word for word. The kind (`Kind`, `FailureKind`) is decided from what is typed, never from a
  message. Where words have to decide, the code says so and why: SSH's "repository not found",
  following JGit's own rule.
- **Secrets.** `domain::secret::Secret` for any key or token. Its `Debug` prints `Secret(***)` and it
  has no `Display`, so the clear value is reachable only through `expose()`. URLs in messages go
  through `repository_url::redact`.
- **Configuration.** The Java agent's environment variables, with Spring's duration syntax (`30s`,
  `PT30S`, bare milliseconds) and the same clamps. `VECTISPIRE_TLS_CA_BUNDLE` is the one new variable;
  see `tls`.
- **Logging.** `tracing`. Plain lines by default, JSON with `VECTISPIRE_LOG_FORMAT=json`, level from
  `VECTISPIRE_LOG_LEVEL` or `RUST_LOG`. The Java agent's log sentences are kept where an operator acts
  on them.
- **Lints.** `unsafe` is denied workspace-wide, and `security/check-unsafe.sh` refuses it anywhere but
  the two process-wide libgit2 calls in `git/src/init.rs`, each under `// SAFETY:`. Clippy runs with
  `-D warnings`; `unwrap`, `expect`, `print!`, `dbg!` and `todo!` are denied outside tests, indexing and
  unchecked arithmetic are held to `security/lint-ceilings.txt`, and lines are 120 columns
  (`rustfmt.toml`). The security checks and what each refuses: [`security/README.md`](security/README.md).
- **Tests.**
  - Unit tests sit beside the code; tests needing a server go in each crate's `tests/`.
  - Those start throwaway containers named `vs-rs-*` through `testkit` and **fail without Docker**.
  - Every test that pins a guard was mutation-checked: the guard was broken, the test went red, and
    the file was restored.
- **Blocking work.** The clone is blocking (libgit2), so it runs under `spawn_blocking`. Container runs
  are async (bollard).

## The reference sets

Two implementations agree only where something compares them. `reference/` holds the Java side's
answers for fixed inputs, and the Rust tests read them:

| Set | Java writer | Rust reader | What it pins |
|---|---|---|---|
| `secrets/` | `SecretsReferenceSetTest` | `scanners/tests/reference_set.rs` | gitleaks reports in, findings out, **byte for byte** as the agent's mapper writes them — fingerprint material |
| `repository-url/` | `RepositoryUrlReferenceSetTest` | `domain/tests/reference_set.rs` | `validate`, `host`, `redact`, `isHttps`, `hasHost` for 90 URLs chosen to tell parsers apart |
| `container/` | `ContainerReferenceSetTest` | `scanners/tests/create_request.rs` | the secrets scan's container-create request, captured off the wire by a stub daemon |
| `iac/` | `IacReferenceSetTest` | `scanners/tests/iac_reference_set.rs` | checkov container results in (`runs/`: stdout, optional `.stderr` and `.case` with `exit=` and `subPath=`), the step's **outcome** out (`outcomes/`): `findings` and the wire JSON, `absent`, or `failure` and its sentence. Runs 01–04 are the pinned image's real output, `iac/regenerate.sh` |
| `sast/` | `SastReferenceSetTest` | `scanners/tests/sast_reference_set.rs` | the same for semgrep — runs 01–06 real, with the bundled rule and an operator rule set (`sast/regenerate.sh`): coverage that makes a report "did not run", the refusal read off stdout, the OWASP edition, the severity table |
| `sast/bundled-rules/` | `BundledRulesReferenceSetTest` | `scanners/tests/rule_placement.rs` | the rules the jar ships, byte for byte — **embedded in the binary from these files** (`scanners::rules::BUNDLED`), so the two agents scan with the same rules |
| `container/{iac,sast}-scan-create.json` | `ScannerCreateReferenceSetTest` | `scanners/tests/scanner_create_requests.rs` | the IaC and SAST scans' container-create requests, with a sub-path |
| `crypto/` | `CryptoReferenceSetTest` | `crypto/tests/reference_set.rs` | both directions: Java's signatures reproduced bit for bit, envelopes sealed by Java opened here; Rust's signatures and announced key verified by Java |
| `failure-reason/` | `FailureReasonReferenceSetTest` | `protocol/tests/failure_reason_reference_set.rs` | `FailureReason.scrub` for 27 reasons chosen to tell two regex engines apart (`\s`, `\b` and `(?i)` are ASCII-only on JDK 19+), lengths in UTF-16 units |
| `artifacts/` | `protocol/tests/artifacts_reference_set.rs` (**the Rust side writes**) | `ScanArtifactsReferenceSetTest` | result bodies the Rust agent sends, read by the agent's mapper and written back: the tree must be the one sent, so a step sent absent cannot arrive empty (decision 0007) |

**Both sides check, and neither silently regenerates.** `./gradlew :vectispire-common:test` fails when
the Java answers differ from the committed files; `./check.sh` fails when the Rust answers differ. A
behaviour change is therefore red until both sides follow, which makes the sets a merge blocker rather
than a snapshot.

- **Regenerate the Java side:** `./gradlew :vectispire-common:test --tests '*ReferenceSetTest*' -Dvectispire.rust.reference.write=true`
- **Regenerate the Rust side** (`crypto/rust-vectors.json`): `VECTISPIRE_REFERENCE_WRITE=1 cargo test -p vectispire-crypto`

  Then rerun the Java side, which reads it.
- **Adding a case:** put the input in the set's `inputs`/`reports`, regenerate the Java side, and make
  the Rust side agree.

No private key is in any file. Each one is the SHA-256 of a label both sides spell the same.

## Decisions of Phase 0

- **Git:** libgit2 (`git2` 0.21, vendored) with libssh2, not gitoxide.
  - gitoxide's SSH transport runs the system `ssh`, which the image is built without on purpose and
    which has had argument-injection advisories.
  - libgit2 checks the host key in-process, through a callback.
  - The cost is C code, plus libssh2's vendored OpenSSL for SSH's cryptography.
  - git2 0.20 carried two unsoundness advisories (RUSTSEC-2026-0183, RUSTSEC-2026-0184); `cargo deny`
    caught them, and 0.21 fixes them.
- **HTTPS does not use libgit2's HTTP stack.** `git/src/https.rs` is a smart-HTTP subtransport on
  reqwest and rustls, registered for `https://` (and `http://`, which the URL checks refuse anyway):
  - every redirect is refused, naming only the destination's host;
  - the token is sent only after the forge's 401, only to its bound host, and is then carried for the
    rest of that clone, as JGit's session does;
  - each status is a number the diagnosis reads (401/403 authentication, 404/410 not found, 429/5xx
    unavailable);
  - nothing of the token reaches the URL, `.git/config`, a message or a log line.
- **Trust:** the Mozilla authorities compiled in (`webpki-roots`), or **only** the PEM bundle in
  `VECTISPIRE_TLS_CA_BUNDLE`. That is replacing, not adding, as the Java agent's truststore does
  (Helm `agents.trustStore`). One trust serves the control plane and the forges.
- **Deployment keys** are parsed before the network: OpenSSH keys (ed25519, ECDSA, RSA) by `ssh-key`,
  PEM ones by their armour, and an encrypted key is refused. `ssh-key` is built without its `rsa`
  feature, which would link a crate with an open timing advisory (RUSTSEC-2023-0071) for nothing,
  since libssh2 signs.
- **The image** is a static musl binary on `scratch`, `USER 1000:1000`, built by a digest-pinned
  builder. `cargo auditable` embeds the dependency list, so Syft and Grype see the 207 crates it links;
  without it they would see nothing and report "no vulnerability".

## Measurements (2026-10-16, arm64, Docker Desktop)

| | Java agent 0.11.0-rc.3 (amd64, emulated) | Rust agent, this commit |
|---|---|---|
| Image, compressed | 111 MB | **4.7 MB** (4.4 MB with the protocol alone; the clone, the four scanners and the runner added 0.3 MB) |
| Idle on a long poll, resident | 300 MB (`VmRSS`) | **3.7 MB** (`VmRSS`, peak the same) |
| Threads | 26 | 3 |
| Grype on the image | 91 matches (6 critical, 39 high), almost all Alpine packages and the JRE | **0 matches** over 207 crates |

**Read the Rust figures for what they are.**
- The binary links the clone, the container runner, the whole protocol with its loop, the crypto and four
  scanners. Plugins, the API discovery and image export are not ported yet.
- No scan-time figure is claimed: the scanners run in their own containers either way.

## Against a real control plane

`crates/agent/tests/against_a_control_plane.rs` starts the published control plane
(`VECTISPIRE_E2E_CONTROL_PLANE_IMAGE`, by default 0.11.0-rc.3 by digest) on a throwaway MySQL, declares a
`delegated` agent with a pinned signing key and a repository with an HTTPS token, and then:

- **through the client**, call by call: hello; the sealing key, whose signature the control plane verifies
  (`Accepted`); a claim whose token the control plane sealed to the announced key and this agent opens;
  a heartbeat; a signed result the control plane accepts; the finished scan's lease refused afterwards; a
  second scan's signed failure report, requeued, and the same attempt refused when reported twice;
- **through the binary**, with the runner it ships: its own hello, announcement and loop take the requeued
  scan and report it, and `SIGTERM` stops it cleanly; its log holds neither the API key nor the seed.

About two minutes, most of it the control plane starting (an amd64 image, emulated on arm64).

## Differences from the Java agent, known and deliberate

- **No URL reading of libgit2's to ask** (the Java side checks JGit's `URIish` host). Instead, the
  HTTPS transport and the SSH host-key callback both compare the host libgit2 is about to reach with
  the validated one, and refuse a difference.
- **An HTTPS timeout covers each whole request**, where JGit's was idle time. SSH and `git://` use
  libgit2's socket timeouts: 30 s to connect, 5 min of silence.
- **An invalid branch name is refused before the network**, with the absent-branch sentence.
- **`@cert-authority` known-hosts lines are skipped.** Host certificates are not verified.
- **A rule set's hash and a plugin's id and digest are percent-encoded as path segments.** The Java
  agent concatenates them as they come; here a `/` or a `..` in one cannot reach another route.
- **A stop cuts the pause after a failed claim short**, where the Java agent sleeps it out; a scan already
  running is still waited for, as there.
- **The hello is retried while the control plane is unreachable** (Phase 0's choice); the Java agent
  fails to start and leaves the restart to its orchestrator. A refusal still stops it at once.
- **The default database root** is `std::env::temp_dir()`, which reads `TMPDIR`; Java's `java.io.tmpdir`
  does not. The agent's work directory is where it is put in the composition (`VECTISPIRE_WORK_DIR`, or the
  `-Djava.io.tmpdir=` of `JDK_JAVA_OPTIONS` the composition sets), since the image has no `/tmp`.
- **It starts only when a Docker daemon answers.** The Java agent starts without one and then fails each
  scan it claims, which spends the scan's attempts; this one exits with "No Docker daemon could be reached"
  and leaves the restart to its orchestrator, so a queue is not drained into failures by a host that cannot
  scan.
- **A matcher's SBOM is forwarded byte for byte** (the workspace turns on `serde_json`'s `preserve_order`);
  a lone surrogate escape, `1e400` and a nesting deeper than 128, which Jackson reads and serde refuses, are
  not in the reference set: no scanner writes them.
- **The API discovery and the language census are not ported**: the first is recorded as a failed step
  ("does not run the API discovery yet"), the second is left absent — "unknown", which resolves nothing.
- **JSON integers beyond 64 bits** in a scanner report would be read as doubles here, where Jackson
  keeps their low 32 bits. No scanner writes one.

- **An uploaded rule file whose last path component is not a plain name** (`..`, `/`, `x/.`) is
  refused with the "could not be written into the workspace" sentence; the Java side resolves it and
  fails on the write — or, for `/`, with a `NullPointerException`. Same outcome: the step fails.
- **The bundled rules' sweep compares with when this process materialised them**, not when it started
  (Rust has no portable process start time): later, which only ever keeps a leftover for the next sweep.

## A defect the reference sets found on the Java side — fixed in 0.11.1

Five readers took a corrupt or missing report for "ran, found nothing", and so resolved the whole backlog
of their type (decision 0007): gitleaks (`SecretsScanner.parse`), semgrep, grype, checkov and syft. They
are fixed on the Java side (`fix(scanning): a corrupt or missing scanner report is absent`), the reference
sets are regenerated from the fixed code, and this port follows: only each tool's own clean answer reads
as empty — `[]` for gitleaks, `"results": []` for semgrep, `"matches": []` for grype, a checkov bare
summary, a catalogue with `"artifacts": []` for syft — and anything else fails the step with the Java
sentence. Pinned by `secrets/`, `iac/runs/16-` to `20-`, `sast/runs/18-` and `23-`,
`dependencies/matches/13-` to `18-`, which write `null`, `absent` or `{"failure": …}`.

## Remaining work, as independent streams

Each stream owns its files; the shared crates change only through the stream that owns them, and only
additively.

| Stream | Owns | Done when |
|---|---|---|
| **Protocol client** — *done* (branch `rust/protocol`) | `crates/protocol/**`; `crates/agent/src/serve.rs` and the loop in `main.rs` | Every route typed from `openapi.json`, with slots and claim concurrency, heartbeats, the unsealing of delegated credentials, and a graceful stop that waits for the running scans to be handed back (as the Java agent does: the protocol has no call to give one back unrun). `AgentProtocolTest`, `AgentHttpTest`, `AgentSealingKeyAnnouncementTest`, `AgentLoopTest`, `AgentLoopConcurrencyTest` and `AgentWireFormatTest` are ported against the stub; the end-to-end suite runs against a real control plane. **What a scanner stream plugs in:** `serve::Execute` (one scan in, `ScanArtifacts` or an `ExecutionFailure` with its kind out), `AgentClient::rule_set` for the SAST stream, `AgentClient::plugin` (with the plugins stream's digest function) for the plugins stream. |
| **Dependencies: Syft + Grype** | `crates/scanners/src/dependencies.rs`, `vulnerability_database.rs`, `reference/dependencies/` | **Done** — their parsers hold to a reference set of real SBOM and match outputs (polyglot tree, empty tree, an exported Alpine image) and 29 edge cases; the database is downloaded under an `fcntl` lock shared with a Java agent and mounted read-only. **Image export is not implemented** (`ExportImages`: a pull and a save through the daemon, in the container crate). |
| **IaC: Checkov** | `crates/scanners/src/iac.rs`, `reference/iac/` | **Done** — `iac::outcome` holds to `reference/iac/` (27 runs), and a real scan runs through the proxy. |
| **SAST: Semgrep** | `crates/scanners/src/sast.rs`, `reference/sast/` | **Done** — `sast::outcome` holds to `reference/sast/` (31 runs); `scanners::rules` places the bundled, operator and uploaded rules, and embeds the jar's. A real scan runs through the proxy. `scanners::output::parse_json` is shared, for the dependency stream. |
| **Workspace, census, API discovery** | `crates/scanners/src/{census,api_discovery}.rs` | The workspace layout (`source/`, `rules/`, 0700) and the sub-path checks are ported in `agent/src/scan.rs`; `LanguageCensus`, `ProjectManifest` and `ApiDiscoveryScanner` — which parse repository content in-process, and so need their own reference set — are not. |
| **Plugins and bundled rules** | `crates/scanners/src/plugins.rs`, `crates/container/src/bounded_output.rs` | Plugin steps, the bounded output holder (`ContainerRun.BoundedOutput`), registry login, and `ImageSignatureVerifier` through the pinned cosign image. |
| **Image and side-by-side conformance** | `Dockerfile.agent`, `measure.sh`, a new CI job | Reproducible builds (built twice, same bytes) and both architectures. Then `scripts/composition-scan-check.sh MODE=agent AGENT_IMAGE=vs-rs-agent` runs the five analyses through each agent in the nightly, compares the results, and stays identical for two weeks. Only then does `release.yml` sign this image. |

Two pieces are shared and owned by nobody in particular, so they change only additively: the
`ScanArtifacts` type, which goes into `crates/protocol/src/wire.rs` and comes from the protocol
stream, and `crates/container`'s runner, from the plugins stream for bounded outputs. Every scanner
stream adds its parser beside `secrets.rs` and its reference set beside `reference/secrets/`, with a
Java writer like `SecretsReferenceSetTest`.

## The control plane's crates (`cp-*`) — Phase 0 of the control plane's port

The same workspace holds the control plane's crates, whose plan is `docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md`, on branch `docs/rust-control-plane-plan` (it joins this branch with it).
**They are the one place the encryption key is named**, and `crates/agent/tests/isolation.rs` exempts `crates/cp-*` from the
test that no source names it — and from nothing else: the agent's graph still links no database client and no server, and the
shared crates (`domain`, `crypto`, …) still may not name the key.

| Crate | What it holds | Held to |
|---|---|---|
| `migrate` (`vectispire-migrate`) | a Flyway 12.4-compatible runner: the migration files read unchanged, `flyway_schema_history` written and validated as Flyway does (checksums proven against Flyway's own), the per-engine lock, the layout rule | Flyway and `MigrationLayoutTest`; Java migrates → Rust validates and the other way round, on MySQL and PostgreSQL (`crates/migrate/oracle/check-oracle.sh`, needs JDK 25) |
| `cp-db` | the pools of both engines, transactions, the `Visibility`-gated query builder (a target's rows cannot be selected without it — compile-fail tests), checked queries with offline caches for both engines (`scripts/sqlx-prepare.sh check`), the schema parity check that stands where `ddl-auto: validate` stood | the Java datasource and transaction semantics; a schema built by the real Flyway |
| `cp-http` | the Spring Security chain as thirteen tower layers in its order, problem documents, the route builder that cannot register a route without its requirement and its answer on visibility | the rc.3 control plane's answers, recorded (`crates/cp-http/tests/golden/`, captured by `capture.sh`); `trybuild` compile-fail cases |
| `cp-contract` | the contract kept identical: `openapi.json` of the 0.11.1 line embedded, routes against document in both directions with a list of routes not yet ported that only shrinks, schemas, published operation ids, the replay of the Java suite's recorded traffic | `ClientContractSpecTest`, `PublishedOperationIdsTest`; the recorder `vectispire-java/…/core/golden/` |
| `cp-arch-tests` | the boundaries as tests: the 28 modules' edge list, layering, cross-module SQL, `unsafe`, the agent's isolation, route authorization rules | `ModularityTest`, `ArchitectureTest`, `CrossModuleQueriesTest`, `RouteAuthorizationTest`, `AuthorizationCoverageTest` |
| `cp-outbound` | `PinnedHttpSender`, `OutboundUrlGuard`, `ReservedEndpoints`, the address classes | the Java classes, by `reference/outbound/` (202 URLs and 30 endpoints × 3 policies × 2 reservation sets, 114 reserved-endpoint readings, 68 addresses); local servers for the pin, the redirect, the ceiling, the deadline, a pinned CA over TLS |
| `cp-runtime` | the settings (108 properties under their Java names and defaults), `/run/secrets`, the logs, the audit mirror, the meters and the actuator's answers, graceful shutdown | `application.yaml` and the Java sources, read by `tests/java_parity.rs`; the actuator's bytes, recorded from rc.3 (`reference/actuator/`) |
| `cp-app` | the binary: `--check-config`, serve, stop gracefully — the HTTP stack and the database are not wired yet; the adapter that writes the audit module's mirror with `cp-runtime`'s file writer | the binary, run, by `tests/binary.rs` |
| `cp-audit` (Phase 1) | the audit log: the hash chain continued from the stored head under V66's one-row lock, the verification, the mirror comparison, the filtered page, the evidence bundle's lines | `reference/audit/` (`AuditChainReferenceSetTest`); the real Java `AuditLogService` on the same database, both ways and at once (`crates/cp-audit/oracle/check-oracle.sh`, needs JDK 25) |
| `cp-settings` (Phase 1) | the catalog (generated from Java's), each value's validation in Java's words, the store of `t_setting` and its two arbitrating writes, the first-install defaults, branding and the product version | `reference/settings/` (`SettingsReferenceSetTest`); both engines |
| `cp-platform` (Phase 1) | the settings screen's rules: what each reader sees of the catalog, every refusal of a save, the audit entry and its SOC signal — the modules it consults that are not ported yet are seams | `SettingsAdministrationService`'s sentences; both engines |

**Where the Rust side differs from the Java one, on purpose** (each is in the code beside the reason):

- **`figment` is not used.** A property's variable is not derived from its key (`vectispire.worker.max-concurrent` ← `VECTISPIRE_SCAN_MAX_CONCURRENT`,
  the brand name ← the first of three), a secret may be a file named after the variable it replaces, and Boot's relaxed binding reads
  `VECTISPIRE_BRANDING_NAME` *before* the chain `application.yaml` gives the brand name — a quirk **kept**, because a deployment that sets
  both sees the name it sees today. What `figment` would add is the layering into a struct, which is the simple part.
- **Not ported, because there is no JVM:** `jvm.*`, `hikaricp.*`, `http.server.*`, `process.*`, `logback.*` and the other Spring/Micrometer meters
  (`/actuator/metrics` lists what Vectispire registers). `prometheus` was never exposed, so it is not offered.
- **Logs:** the plain line is Spring's console format; the instant is **UTC**; the level is `RUST_LOG`, or `LOGGING_LEVEL_ROOT`
  (Spring's variable for the root logger), or `info` — the per-package `LOGGING_LEVEL_*` are not mapped. `VECTISPIRE_LOG_FORMAT=json` is new.
- **Read where used, not in the settings:** `VECTISPIRE_SEMGREP_RULES_DIR`, `HOSTNAME`, `XDG_RUNTIME_DIR` (scanning's own); `spring.datasource.hikari.*`,
  Flyway's and JPA's (`cp-db`, `cp-migrate`); `management.*` and `server.shutdown` are constants of the crate.
- **A duration is never negative here**, and the Java probing of a developer's own Docker socket paths (`~/.orbstack/…`) is not ported.
- **`PinnedCa`** carries the form checks (PEM only, ≤ 16 384 characters, ≤ 8 certificates, nothing but certificates); the X.509 reading
  (CA flag, key usage, validity) needs a parser this workspace does not carry and comes with the forge connections.
- **The sender** sends `User-Agent: Vectispire`, does not ask for `gzip` and does not decode it, and honours no proxy.
- **One URL the guard reads differently:** `http://[fe80::1%eth0]/`, whose answer under the JDK depends on the host's interfaces — here it is
  unreadable everywhere, the safe side (the agent's `java_uri` port takes no scope id).

`cp-runtime`'s tests that name the control plane's own files (`tests/java_parity.rs`) read `../../../vectispire-java`: they run in a full checkout.
