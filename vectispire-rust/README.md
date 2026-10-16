# vectispire-rust — the remote agent, in Rust

**Port in progress, not shipped.** Nothing here is built by `release.yml` or published, and no
deployment runs it. The agent that ships is `vectispire-java/vectispire-agent`. This binary speaks the
whole agent protocol — it announces itself and its signed sealing key, claims up to its limit of scans
at once, opens the credentials they carry, beats for each, and hands back a signed result or a signed,
scrubbed failure report — but **it does not run scans yet**: no scanner is wired to its loop, so a scan
it is handed goes back to the queue as a transient failure. Never point it at a control plane whose scans
matter.

The costed study behind the port is on branch `docs/rust-agent-study`
(`docs/analysis/en/2026-10-16_rust_agent_port_study.en.md`). This directory is its Phase 0, built as
the foundation the rest of the port extends rather than as a throwaway spike.

```sh
./check.sh     # fmt, clippy -D warnings, every test (Docker required), cargo deny
./measure.sh   # image size, idle memory, Grype — GRYPE_DIGEST=<the digest ScannerImages pins>
```

The toolchain is pinned by `rust-toolchain.toml`.

## Layout

| Crate | Owns | Java counterpart |
|---|---|---|
| `agent` | the binary: configuration (same variables as the Java agent), logging, `check docker` / `check clone`, and the loop (`serve.rs`: slots, heartbeats, a lost lease, the graceful stop) | `vectispire-agent` (`AgentRunner`, `AgentLoop`, `Slots`) |
| `protocol` | every agent route and its bodies (`ScanTask` in, `ScanArtifacts` out), the HTTP client of the control plane, the opening of sealed credentials, the failure reason's scrub, the concurrency limit | `AgentProtocol`, `AgentHttp`, `ScanTask`, `ScanArtifacts`, `FailureReason`, `AgentConcurrency` |
| `crypto` | result, failure and sealing-key signatures; sealed envelopes | `domain.crypto` |
| `git` | the clone: SSH (libgit2 and libssh2, host keys pinned or recorded), HTTPS (this crate's own smart-HTTP transport on rustls), failure kinds and sentences | `GitClone`, `RedirectRefusingConnections`, `CloneFailureException` |
| `container` | scanner containers through the Docker API or the socket proxy, in one closed shape | `ContainerRunner`, `ContainerRun`, `ScannerLimits` |
| `scanners` | each scanner's run and the parser of its output (secrets today) | `scanning.scanners` |
| `domain` | repository-URL checks (a port of `java.net.URI`'s parser), metadata addresses, failure kinds, the contract number, `Secret` | `RepositoryUrl`, `LinkLocalHosts`, `FailureKind`, `AgentContract` |
| `tls` | the one trust every HTTPS connection uses | the JVM truststore |
| `testkit` | test support only: the reference sets, throwaway containers, the test forge and the stub control plane (`control_plane.rs`, on a loopback port, one thread per connection) | — |

**The agent's isolation is a property of the graph** (decision 0003). The workspace shares no code
with the control plane. `crates/agent/tests/isolation.rs` reads `cargo metadata` and fails if the agent
links any database client, server framework or test-support crate. `deny.toml` bans the same crates
workspace-wide. A second test fails if any source names the control plane's encryption key.

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
- **Lints.** `unsafe` is denied workspace-wide. Its only uses are the two process-wide libgit2 calls
  in `git/src/init.rs`, each with its reason. Clippy runs with `-D warnings`, `unwrap` and `expect` are
  warned outside tests, and lines are 120 columns (`rustfmt.toml`).
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
| Image, compressed | 111 MB | **4.5 MB** (4.4 MB before the whole protocol and the loop) |
| Idle on a long poll, resident | 300 MB (`VmRSS`) | **3.2 MB** (`VmRSS`, peak the same) |
| Threads | 26 | 3 |
| Grype on the image | 91 matches (6 critical, 39 high), almost all Alpine packages and the JRE | **0 matches** over 207 crates |

**Read the Rust figures for what they are.**
- The binary links the clone, the container runner, the whole protocol with its loop, and the crypto. The other four
  scanners, plugins and rules are not ported yet.
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
- **JSON integers beyond 64 bits** in a scanner report would be read as doubles here, where Jackson
  keeps their low 32 bits. No scanner writes one.

## A defect the reference set found on the Java side

**A gitleaks report that is not JSON, or not an array, gives an empty list**
(`SecretsScanner.parse`). The scan then sends that empty list as "analysed, nothing found", which
resolves every secret issue of the target — what decision 0007 forbids. The port reproduces it, so
that the two agents never disagree about a backlog; it is pinned by `secrets/reports/04-not-json.json`.
Fix it on the Java side and the reference set carries the fix across.

## Remaining work, as independent streams

Each stream owns its files; the shared crates change only through the stream that owns them, and only
additively.

| Stream | Owns | Done when |
|---|---|---|
| **Protocol client** — *done* (branch `rust/protocol`) | `crates/protocol/**`; `crates/agent/src/serve.rs` and the loop in `main.rs` | Every route typed from `openapi.json`, with slots and claim concurrency, heartbeats, the unsealing of delegated credentials, and a graceful stop that waits for the running scans to be handed back (as the Java agent does: the protocol has no call to give one back unrun). `AgentProtocolTest`, `AgentHttpTest`, `AgentSealingKeyAnnouncementTest`, `AgentLoopTest`, `AgentLoopConcurrencyTest` and `AgentWireFormatTest` are ported against the stub; the end-to-end suite runs against a real control plane. **What a scanner stream plugs in:** `serve::Execute` (one scan in, `ScanArtifacts` or an `ExecutionFailure` with its kind out), `AgentClient::rule_set` for the SAST stream, `AgentClient::plugin` (with the plugins stream's digest function) for the plugins stream. |
| **Dependencies: Syft + Grype** | `crates/scanners/src/dependencies.rs`, `vulnerability_database.rs`, `reference/dependencies/` | Their parsers match the Java side's on a reference set of real SBOM and match outputs. The database is downloaded under a lock and mounted read-only. |
| **IaC: Checkov** | `crates/scanners/src/iac.rs`, `reference/iac/` | The same, for Checkov. |
| **SAST: Semgrep** | `crates/scanners/src/sast.rs`, `reference/sast/` | The same, for Semgrep. Its rule placement comes with it (`RulePlacement`, `BundledRules`). |
| **Workspace, census, API discovery** | `crates/scanners/src/{workspace,census,api_discovery}.rs` | The workspace layout (`source/`, `rules/`, 0700) is ported, with `LanguageCensus` and `ApiDiscoveryScanner`, which parses repository content in-process and so has its own reference set. |
| **Plugins and bundled rules** | `crates/scanners/src/plugins.rs`, `crates/container/src/bounded_output.rs` | Plugin steps, the bounded output holder (`ContainerRun.BoundedOutput`), registry login, and `ImageSignatureVerifier` through the pinned cosign image. |
| **Image and side-by-side conformance** | `Dockerfile.agent`, `measure.sh`, a new CI job | Reproducible builds (built twice, same bytes) and both architectures. Then `scripts/composition-scan-check.sh MODE=agent AGENT_IMAGE=vs-rs-agent` runs the five analyses through each agent in the nightly, compares the results, and stays identical for two weeks. Only then does `release.yml` sign this image. |

Two pieces are shared and owned by nobody in particular, so they change only additively: the
`ScanArtifacts` type, which goes into `crates/protocol/src/wire.rs` and comes from the protocol
stream, and `crates/container`'s runner, from the plugins stream for bounded outputs. Every scanner
stream adds its parser beside `secrets.rs` and its reference set beside `reference/secrets/`, with a
Java writer like `SecretsReferenceSetTest`.
