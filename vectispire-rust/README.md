# vectispire-rust — the remote agent and the control plane's foundations, in Rust

**Port in progress, not shipped.** Nothing here is built by `release.yml` or published, and no
deployment runs it. The agent that ships is `vectispire-java/vectispire-agent`. This binary speaks the
whole agent protocol — it announces itself and its signed sealing key, claims up to its limit of scans
at once, opens the credentials they carry, beats for each, and hands back a signed result or a signed,
scrubbed failure report — and it runs a repository scan: the clone, the project manifest, the language
census and the API discovery read in process, the four analyses (dependencies, secrets, IaC, SAST), and the
task's plugins (`crates/scanners/src/plugins.rs`: a declared signer verified by the pinned cosign image before
the pull, the plugin in the closed shape with a bounded output, its report read under SARIF's guards, each plugin
produced, not applicable, absent or refused), as the Java agent does (`crates/agent/src/scan.rs`). An image target is exported through the daemon
and inventoried from the archive, as on the Java agent (since 2026-11-15, task 2.10). Never point it at a
control plane whose scans matter.

The costed study behind the port is on branch `docs/rust-agent-study`
(`docs/analysis/en/2026-10-16_rust_agent_port_study.en.md`). This directory is its Phase 0, built as
the foundation the rest of the port extends rather than as a throwaway spike.

```sh
./check.sh     # fmt, clippy -D warnings, every test (Docker required), cargo deny, then the
               # security checks: unsafe, lint ceilings, cargo vet, semgrep (security/README.md)
./measure.sh   # image size, idle memory, Grype — GRYPE_DIGEST=<the digest ScannerImages pins>
./security/reproducible-image.sh linux/arm64   # the image built twice from nothing: one digest, or a failure
# the Java and the Rust agent on the same composition, compared (from the repository root):
CONTROL_PLANE_IMAGE=… JAVA_AGENT_IMAGE=… RUST_AGENT_IMAGE=… ../scripts/agent-conformance.sh
```

The toolchain is pinned by `rust-toolchain.toml`.

## Layout

| Crate | Owns | Java counterpart |
|---|---|---|
| `agent` | the binary: configuration (same variables as the Java agent, and the secrets read from the `configtree:` it names, as the composition passes them), logging, `check docker` / `check clone`, the loop (`serve.rs`: slots, heartbeats, a lost lease, the graceful stop) and the scan runner (`scan.rs`: workspace, clone, sub-path, the steps, rule placement) | `vectispire-agent` (`AgentRunner`, `AgentLoop`, `Slots`) |
| `protocol` | every agent route and its bodies (`ScanTask` in, `ScanArtifacts` out), the HTTP client of the control plane (feature `client`, which only the agent turns on), the opening of sealed credentials, the failure reason's scrub, the concurrency limit; and the control plane's half: `ScanArtifacts::read` as Jackson reads a result, the claim, hello and failure bodies the server writes and reads (`server`) | `AgentProtocol`, `AgentHttp`, `ScanTask`, `ScanArtifacts`, `FailureReason`, `AgentConcurrency`; `AgentsController`, `AgentProtocolService`'s readers, `CoreConfiguration`'s mapper |
| `crypto` | result, failure and sealing-key signatures; sealed envelopes | `domain.crypto` |
| `git` | the clone: SSH (libgit2 and libssh2, host keys pinned or recorded), HTTPS (this crate's own smart-HTTP transport on rustls), failure kinds and sentences | `GitClone`, `RedirectRefusingConnections`, `CloneFailureException` |
| `container` | scanner containers through the Docker API or the socket proxy, in one closed shape; the executor seam both backends sit behind (`ContainerExecutor`, `Executor`) | `ContainerRunner`, `ContainerRun`, `ScannerLimits`, `ContainerExecutor` |
| `kubernetes` | the Kubernetes executor (decision 0045): each run a pod in the scans' namespace, the API server reached with the agent's own HTTP client and a WebSocket `exec` written here, the copy in and back over `tar`, the matcher's cache volume, the start's checks (sweep, Pod Security, isolation probe). **Linked by the agent alone** — `deny.toml` bans it elsewhere | `agent.kubernetes.*`, `ExecutorChoice` |
| `scanners` | each scanner's run and the parser of its output (secrets today) | `scanning.scanners` |
| `domain` | repository-URL checks (a port of `java.net.URI`'s parser), metadata addresses, failure kinds, the contract number, `Secret`; for the control plane (task 2.4), the fingerprint and the target vocabulary — `FindingType`, `ScanTarget`, `ToolKeys`, `BoundedText`, `DependencyGraph`, `Sbom`, the licence blocklist, retention, `ScanStatus` — and Spring's cron parser; differences from Java in [`crates/domain/README.md`](crates/domain/README.md) | `RepositoryUrl`, `LinkLocalHosts`, `FailureKind`, `AgentContract`, `IssueFingerprint`, `CronExpression` |
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
  - **A test that needs a database gets one of its own**, from `cp-db`'s `testing` (feature `test-support`, turned
    on from `[dev-dependencies]` only): migrated by `vectispire-migrate` (`TestDatabase::start`) or empty
    (`TestDatabase::empty`), dropped with the value. Without variables it is a throwaway server of the campaign's
    engine; with `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` (a server URL with no database,
    `jdbc:mysql://127.0.0.1:3306`, and `…_USER`, `…_PASSWORD` an account that may create databases — the Java
    suite's `VECTISPIRE_TEST_DB_*` convention) it is a database `vs_rs_<epoch>_<pid>_<n>` on that server. Two tests
    share the server and nothing else, so a statement on the server's own tables (`pg_stat_activity`,
    `performance_schema`) filters by the test's database. **`VECTISPIRE_TEST_ENGINES` selects the engines**:
    unset means both, otherwise `mysql`, `postgresql` or both comma-separated; a misspelt or empty value fails
    the run, every engine loop asks `testing::runs_on` and prints `left out: …` for a case it skips, and
    `TestDatabase::empty` refuses an engine not selected. CI's `rust` job runs on pull requests with
    `mysql` and one MySQL server as a job service, and no job runs PostgreSQL since 2026-11-12 (decision 0043 §3).
    Locally:

    ```sh
    docker run -d --name vs-rs-shared-mysql -e MYSQL_ROOT_PASSWORD=local -p 127.0.0.1:13306:3306 mysql:9.4.0@sha256:…
    docker run -d --name vs-rs-shared-postgres -e POSTGRES_PASSWORD=local -p 127.0.0.1:15432:5432 postgres:17.6-alpine@sha256:…
    VECTISPIRE_TEST_MYSQL_URL=jdbc:mysql://127.0.0.1:13306 VECTISPIRE_TEST_MYSQL_USER=root \
    VECTISPIRE_TEST_MYSQL_PASSWORD=local VECTISPIRE_TEST_POSTGRES_URL=jdbc:postgresql://127.0.0.1:15432 \
    VECTISPIRE_TEST_POSTGRES_USER=postgres VECTISPIRE_TEST_POSTGRES_PASSWORD=local cargo test --workspace
    ```

    (the digests are `testing.rs`'s). A shared MySQL is given the composition's flags at its first use (time zone,
    packet size, connections); a database a killed run left is dropped by the first run a day later. The suites
    that start the published Java control plane keep their own MySQL 8.4 on a network with it.
  - CI runs the tests with **cargo-nextest** (`.config/nextest.toml`): each test a process of its own, every binary
    at once, then `cargo test --doc`. `./check.sh` runs `cargo test`, the same tests one binary after another.
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
| `workspace/` | `WorkspaceReferenceSetTest` | `scanners/tests/workspace_reference_set.rs` | 176 trees built from `cases/` (text, base64, repeated runs, links to a decoy directory beside the tree) and what the scan learns from each in process (`answers/`, one JSON line per tree): the **census** (whole and stopped early), the **project manifest**, and the **API discovery**'s endpoints and contracts or its failure sentence. Hostile shapes throughout: links out of the tree, files past 2 MiB, 200 levels of directories, bytes that are not UTF-8 (the JDK's decoder delimits an encoded surrogate unlike the WHATWG), the JDK's XML limits under secure processing (depth 100, 200 attributes, names of 1,000), Jackson's (depth 1,000, numbers of 1,000 digits, names of 50,000), `Properties`' escapes and continuations, patterns written to backtrack. Regenerated with `./gradlew :vectispire-common:test --tests '*WorkspaceReferenceSetTest*' -Dvectispire.rust.reference.write=true`; `scanners/tests/workspace_corruption.rs` corrupts every file of it through every reader |
| `repository-url/` | `RepositoryUrlReferenceSetTest` | `domain/tests/reference_set.rs` | `validate`, `host`, `redact`, `isHttps`, `hasHost` for 90 URLs chosen to tell parsers apart |
| `container/` | `ContainerReferenceSetTest` | `scanners/tests/create_request.rs` | the secrets scan's container-create request, captured off the wire by a stub daemon |
| `iac/` | `IacReferenceSetTest` | `scanners/tests/iac_reference_set.rs` | checkov container results in (`runs/`: stdout, optional `.stderr` and `.case` with `exit=` and `subPath=`), the step's **outcome** out (`outcomes/`): `findings` and the wire JSON, `absent`, or `failure` and its sentence. Runs 01–04 are the pinned image's real output, `iac/regenerate.sh` |
| `sast/` | `SastReferenceSetTest` | `scanners/tests/sast_reference_set.rs` | the same for semgrep — runs 01–06 real, with the bundled rule and an operator rule set (`sast/regenerate.sh`): coverage that makes a report "did not run", the refusal read off stdout, the OWASP edition, the severity table |
| `sast/bundled-rules/` | `BundledRulesReferenceSetTest` | `scanners/tests/rule_placement.rs` | the rules the jar ships, byte for byte — **embedded in the binary from these files** (`scanners::rules::BUNDLED`), so the two agents scan with the same rules |
| `container/{iac,sast}-scan-create.json` | `ScannerCreateReferenceSetTest` | `scanners/tests/scanner_create_requests.rs` | the IaC and SAST scans' container-create requests, with a sub-path |
| `crypto/` | `CryptoReferenceSetTest` | `crypto/tests/reference_set.rs` | both directions: Java's signatures reproduced bit for bit, envelopes sealed by Java opened here; Rust's signatures and announced key verified by Java |
| `failure-reason/` | `FailureReasonReferenceSetTest` | `protocol/tests/failure_reason_reference_set.rs` | `FailureReason.scrub` for 27 reasons chosen to tell two regex engines apart (`\s`, `\b` and `(?i)` are ASCII-only on JDK 19+), lengths in UTF-16 units |
| `access/` | `AccessReferenceSetTest` (`vectispire-core`) | `cp-access/tests/authz_reference_set.rs`, `authz_on_both_engines.rs` | the role flags, the markers' roles, `VisibilityMode.of`, key restrictions, `VisibilityService` over 960 accounts × grants × modes × restrictions, `RowVisibility`'s 404s, four-eyes and its setting — the control plane's, regenerated with `./gradlew :vectispire-core:test --tests '*AccessReferenceSetTest*' -Dvectispire.rust.reference.write=true` |
| `sign-in/` | `SignInReferenceSetTest` | `cp-access/tests/sign_in_reference_set.rs` | the second factor and the sign-in throttle: Base32 both ways (Java's `toUpperCase(ROOT)` leniency — `ß` reads as `SS`), TOTP codes (RFC 6238's own vectors, the steps around the epoch), 26 submitted codes against their step (Java's `trim`, a secret with no key), the enrolment URI as `URLEncoder` writes it, 57 typed names and the key their failures count under (NFKD, marks, the root locale's cases, the letters MySQL's collation equates), 108 client addresses and their bucket as `InetAddress.ofLiteral` reads them (`cp-http`'s `client_bucket`), and the window's edges to the nanosecond |
| `access/scim/` | `ScimReferenceSetTest` (`vectispire-core`) | `domain/tests/scim_reference_set.rs` | `ScimProvisioningService` over mocked repositories: 82 users' filters (the lookup, or the controller's 400 with `scimType` and `detail`; Java's `\s`, `.` and ASCII-only `(?i)`), 34 pages, 55 PATCH member entries (`Long.parseLong`, Jackson 3's `asString()`; four that Java answers 500) and 34 `remove` paths |
| `teams/` | `TeamRulesReferenceSetTest` | `domain/tests/teams_reference_set.rs` | `TeamRules`: names, descriptions (clipped on a character boundary) and target kinds, straddling the limits with emoji |
| `fingerprints/` | `FingerprintReferenceSetTest` | `domain/tests/fingerprint_reference_set.rs` | **the issue fingerprint**, the tool keys and `BoundedText.clip`: 116 hand-picked cases (`IssueFingerprintTest`'s and `ToolFingerprintTest`'s, then each Java quirk: `?` for an unpaired surrogate, `strip()` and the no-break spaces, null joined as empty, an empty purl falling back to the name, `Locale.ROOT`, UTF-16 lengths), a seeded corpus of 1,000 inputs over those quirks, and 3,000 strings around the capital sigma, which Java lowers by its word `BreakIterator` |
| `vocabulary/` | `VocabularyReferenceSetTest` | `domain/tests/vocabulary_reference_set.rs` | the finding types and scan statuses, 18 SBOMs read by `Sbom`, `DependencyGraph` (Jackson's `asText`) and `LicenseBlocklist`, `RetentionPolicy.prunable` over 18 generated histories, `intSetting` (`Integer.parseInt` reads any Unicode digit), the digits `Character.digit` reads |
| `cron/` | `CronReferenceSetTest` (`vectispire-core`) | `domain/tests/cron_reference_set.rs` | Spring's `CronExpression` for 187 expressions — the refusal sentence, or the next six fire times from four starts — and `CronExpressions`' crontab reading of each |
| `siem/` | `SiemReferenceSetTest` | `domain/tests/siem_reference_set.rs` | the SIEM's domain, byte for byte: the 39 events' catalogue, the signal of each of the 103 audit operations, 28 CEF lines (escapes, controls, a key given twice to a `LinkedHashMap`, Java's `isBlank`), 16 syslog headers and 5 octet-counted frames, 136 endpoints and their refusals (an IPv4-mapped address in brackets, a full-width port, a webhook's port as `URI.getPort` reads it, a numeric syslog host as `Inet4Address.ofLiteral` reads it, a port's leading zeros), the protocols, the severity minimums and the triage signals; 59 collector-CA bundles built from 18 certificates BouncyCastle 1.86 wrote (`collector-ca/generate.jsh`) — the subject `X500Name` renders (every string type, the escapes, multi-valued RDNs, values that are not strings), the dates, the DER, and each refusal of the PEM text and of the certificate, read as stored (`parse`) and as pasted (`parsePasted`, which refuses a `-----BEGIN` line the reader skipped) |
| `siem/module.json` | `SiemModuleReferenceSetTest` (`vectispire-core`) | `cp-siem/tests/engines.rs` (both engines) | the SIEM module over Java's real services and mocked collaborators: the payload 16 audit entries and broken chains queue (members, order, `null`, the 1,024-unit cut and its `?`), what 25 stored rows become at delivery (the webhook's JSON body and header, the syslog message, or the refusal and whether it abandons the row), what 40 saves refuse, write, audit and tell the collector being left, what 18 connection tests answer and send |
| `plugins/{manifests,images,sarif,steps}/` | `PluginsReferenceSetTest` | `scanners/tests/plugins_reference_set.rs` | committed `cases.json`, Java's `answers.json`: 121 manifests as the agent's mapper reads them (digest, command, or the refusal — the signer's key read as BouncyCastle reads it: curves, RSA bits, PEM blocks), 144 image relocations and mirrors, 95 SARIF reports (Jackson's constraints, absent vs empty, suppressions, severities, `SarifPaths`' refusals — fingerprint material), and 63 end-to-end scenarios through `PluginSteps` with a stand-in executor: each plugin's state on the wire, its reason, and every container request (cosign's flags and login, the plugin's mounts, user, network, timeout, bounded output). A refusal in Jackson's own words is compared up to "not readable JSON:" |
| `plugins/{archives,measurements,credentials}/` | `PluginRunsReferenceSetTest` | `container/tests/plugin_runs_reference_set.rs` | the bounded output read back: 36 tar archives as the daemon answers them (ustar, PAX, GNU long names, base-256, links, truncations — the size refused on the header), the holder's `df`, and docker-java's pull credentials for 21 Docker configurations (the registry key, Hub's legacy address, the one-entry file handed to cosign, the redaction) |
| `plugins/creates/` | `PluginRunsReferenceSetTest` | `scanners/tests/plugin_creates.rs` | the holder's, the plugin's and cosign's container-create requests, captured off the wire: the tmpfs volume and its options, `VolumesFrom`, `fsize`, the key and the registry login mounted read-only with `DOCKER_CONFIG` |
| `kubernetes/` | `KubernetesReferenceSetTest`, `ExecutorChoiceReferenceSetTest` (`vectispire-agent`) | `kubernetes/tests/reference_set.rs` | the Kubernetes executor's pure parts: the pod 8 runs become (security context, limits, volumes and their sizes, the wrapper, placement and the cache's node — **byte for byte, in Java's key order**), the probes' pods and scripts, the copy back's script, the API server's address accepted or refused (25 environments × resolvers), the probe target, 27 exec streams sorted by channel (fragments, ceilings, status documents), 30 pod statuses read as a failure, 24 archives commons-compress wrote read back as files or refused, a plugin's bounded output (its volume and both mounts, the holder's probe and 23 answers to it) and its registry login (the mounted secret's entry for 4 images under 11 secrets, the file handed over, the redaction, an unreadable secret's sentence and `registryAccessFor`), the choice's refusals — regenerated with `./gradlew :vectispire-agent:test --tests '*ReferenceSetTest*' -Dvectispire.rust.reference.write=true` |
| `artifacts/` | `protocol/tests/artifacts_reference_set.rs` (**the Rust side writes**) | `ScanArtifactsReferenceSetTest` | result bodies the Rust agent sends, read by the agent's mapper and written back: the tree must be the one sent, so a step sent absent cannot arrive empty (decision 0007) |
| `artifacts/java-read.json`, `artifacts/server-wire.json` | `AgentWireReferenceSetTest` (`vectispire-core`) | `protocol/tests/java_read_reference_set.rs`, `server_wire_reference_set.rs` | 456 result bodies and what the control plane's Jackson 2 bean made of each (refused, `null`, or every step and field read), the encodings, surrogates, coercions and `StreamReadConstraints` limits included; the claim, hello and failure answers Spring MVC's Jackson 3 writes, byte for byte; the hello, sealing-key and failure requests as read; the contract comparison; every refusal's sentence |

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
  scanners, and the in-process readers of the tree. Image export is ported since 2026-11-15, plugins since
  2026-11-19 (measured before them).
- No scan-time figure is claimed: the scanners run in their own containers either way.

## The image, and the side-by-side conformance

**Reproducible, per platform.** `security/reproducible-image.sh <platform>` builds `Dockerfile.agent` twice
without cache, with the commit's time as `SOURCE_DATE_EPOCH` and BuildKit rewriting the layers' timestamps,
into OCI archives, and fails unless the two manifests (and the two binaries) are the same. CI runs it for
linux/amd64 in `rust-image` and for linux/arm64 in `rust-image-arm64`, on GitHub's arm runner: each
platform is built natively, never cross-compiled, so one builder pinned by its index digest is the whole
toolchain. What reaches the binary — rustc, musl, gcc, binutils — is in that builder; `perl`, `make` and
the kernel headers (`apk add`, for libssh2's vendored OpenSSL) are taken from Alpine 3.22's repository at
build time, so two builds on two days are the same only while 3.22 has not moved them.

**A drop-in for the Java agent's image**: user 1000:1000, `HOME=/home/vectispire` (owned by 1000, 0700,
where Jib's is 0777), a `/tmp` (1777), and the Java agent's variables read where it reads them —
`VECTISPIRE_*`, `DOCKER_HOST`, `SPRING_CONFIG_IMPORT`'s config trees for the token and the signing key,
`JDK_JAVA_OPTIONS`' `-Djava.io.tmpdir=` and `-Duser.home=`. On the Docker Compose install, setting the
`agent` service's image to this one is the whole change:

- **No shell needed.** The composition's `agent-work-dir` (one `chown` and one `chmod` of the agent's
  directory, as root, before the agent starts) runs the **control plane's** image since 2026-11-20, not the
  agent's: it needs `sh`, which this image does not have on purpose, and the control plane's is already
  there — `agent` depends on it in the same file. The Java image keeps working unchanged; nothing is added
  to this one. (A subcommand of the binary doing the same was the alternative: it would have had to be
  run as root from this image while the Java image needs `sh -c`, so the composition could not name one
  entrypoint for both.)
- **`/app/LICENSE` and `/app/NOTICE`**, where the Java images carry theirs, and beside them what a static
  binary cannot carry inside itself: `/app/THIRD-PARTY-LICENSES`, every crate linked in with the licence it
  declares and every licence file it ships, and the C libraries built from source with their own licences —
  libgit2 (GPL-2.0 with its linking exception), libssh2, zlib, OpenSSL — and `/app/RUST-STD-COPYRIGHT.html`,
  the standard library's notices from the pinned toolchain (musl and libunwind, linked statically). `LICENSE`
  is the repository's, copied into this build context; `NOTICE` is this image's own (the repository's
  describes the jars and Alpine). The list is generated from `Cargo.lock` and **committed**, not generated
  in the build, so the image stays reproducible by construction: `security/third-party-licences.py` writes
  it, and `security/third_party_licences_test.py` (in `check.sh` and CI's `rust` job) fails when it is stale,
  when `NOTICE` does not name a licence the graph carries, or when `LICENSE` differs from the repository's —
  `security/mutants/agent-compose-dropin.py`. A dependency change therefore runs the script in the same diff.

With the chart, the trust store differs: the chart sets `-Djavax.net.ssl.trustStore=` (PKCS12)
from `agents.trustStore`, which this agent does not read. It reads a PEM bundle from `VECTISPIRE_TLS_CA_BUNDLE`,
which the chart passes when the store's Secret also holds its PEM form (`agents.trustStore.pemKey`); named alone,
the store stops this agent at start — see "In a cluster" below.

**Side by side.** `../scripts/agent-conformance.sh` runs `scripts/composition-scan-check.sh` in agent mode
twice against one control plane image — through the Java agent, then the Rust agent — on a fixture planted
identically (`FIXTURE_TOKEN`, a commit with fixed dates), keeps what the control plane recorded of each
scan (`DETAIL_DIR`: the scan's detail and its target's issues), and `../scripts/compare-agent-runs.py`
compares them after setting aside ids, instants and durations: status, failed steps and their sentences,
`examinedTypes` null vs empty, plugins, findings, and every issue with its fingerprint. A difference must be
listed in `../ci/agent-conformance/accepted-differences.txt` with its reason, and a line no difference used
fails too. The nightly's `agent-conformance` job runs it on the images built at the night's commit, and keeps
each side's whole control-plane and agent logs, timestamped (`java.containers.log`, `rust.containers.log`:
`CONTAINER_LOG`), so that a red night says what the agent was doing, not only that a scan never finished.
With `AGENT_RUST_LOG=info,vectispire_runner=debug` (the nightly sets it) the Rust agent also logs each step's
start and end under the scan's span: the last step started and never done is where a scan is.

*Why:* one early run left the Rust agent's first scan `scanning` for 900 s on an overloaded machine, a rerun
passed, and the log had gone with the containers. Measured again on 2026-11-20 — once unloaded (Java and Rust,
identical), then with 10 and with 20 busy loops in the Docker VM plus as many on the host (the control plane
needed 228 s and 378 s to become healthy): every check passed, the first scan in 98 s and 101 s, no missed
heartbeat, no failed claim, every step ending well inside its bound (IaC 36–45 s, SAST 29–34 s). Nothing in
the agent waits without a bound — the clone runs on a blocking thread under libgit2's timeouts, each scanner
under its 15-minute wait, every control-plane call under its own timeout, and the socket proxy cuts a stream
silent for 10 minutes. What would hold a scan `scanning` past 900 s without any defect is a step legitimately
that slow, or **a claim whose answer is lost**: a control plane too starved to answer within the wait plus 30 s
assigns the scan, the agent gives up on the call ("Could not claim"), and the scan waits for its lease to
lapse. The Java agent has the same bound and the same exposure; closing it is a protocol change (a claim the
agent can repeat and get the same scan back), not an agent fix.

**The rule for signing.** `release.yml` does not build, sign or publish this image. It starts to only after
**fourteen consecutive nightly `agent-conformance` runs green** — no difference outside the accepted list,
both agents passing their own check — and that change is its own pull request, citing the runs. A red
night restarts the count, and so does a line added to the accepted list.

## In a cluster, through the chart

`AGENT=rust scripts/kubernetes-scan-check.sh` (from the repository root) installs the Helm chart in k3s — a server and
an agents' node — with `agents.executor: kubernetes` and this agent's image, and runs one scan of the composition
check's fixture: the agent proves its scan pods cut off before it claims anything, every scanner runs as a pod in the
scans' namespace and finds what was planted for it. The same script, the same values and the same Secrets as for the
Java agent's image; only the image differs.

**The trust store: the chart passes a PEM form beside the PKCS12, and this agent does not read PKCS12.** Weighed:

- *Reading the store here* means the PKCS12 container, its MAC, and the decryption of its certificate bags — keytool
  encrypts them under the store's password (PBES2, PBKDF2 and AES since JDK 12, RC2 and 3DES in older stores): some ten
  crates of cryptography new to the workspace, each to audit for `cargo vet`, to read one file an operator wrote. And it
  is semantic, not a format: the JDK trusts only the bags carrying Oracle's trusted-key-usage attribute (a store made by
  `openssl pkcs12 -nokeys` without `-jdktrust` trusts *nothing* in Java), skips the encrypted bags when no password is
  given, and reads the password from `-Djavax.net.ssl.trustStorePassword=`, which the chart does not set but an
  operator's `extraEnv` does. Each of those is a way to trust more or less than Java, to pin to a reference set Java
  writes.
- *The chart passing a PEM form* is one more entry in the Secret the operator already makes
  (`keytool -exportcert -rfc` per alias, or `openssl pkcs12 -nokeys`), and nothing new here: the PEM bundle already
  *replaces* the compiled-in authorities, as the store replaces the JVM's.

Chosen: the second. `agents.trustStore.pemKey` names the PEM entry of the store's Secret; the chart mounts both and sets
`VECTISPIRE_TLS_CA_BUNDLE` beside `-Djavax.net.ssl.trustStore=`, so one Secret serves either image and switching back
and forth changes nothing in the values. What must not happen is the case left between the two: **a store named and no
bundle**. Before this change that agent started on its compiled-in authorities — the operator's private CA refused,
which is loud, but every public CA their store had left out trusted again, which is not. It now refuses to start,
saying which variable names which store and what to give (`TrustError::JavaTrustStoreOnly`, read from
`JDK_JAVA_OPTIONS` and `JAVA_TOOL_OPTIONS`, both of which a JVM honours; `crates/tls/tests/java_trust_store.rs`,
`security/mutants/agent-in-cluster.py`). The chart refuses a `pemKey` without the store's Secret, or naming the store's
own entry. No reference set: nothing semantic is decided here — the two forms are one set by the operator's export,
and the bundle's replacing rule is the one already held.

**The matcher's database** is put in the agent's work directory by an ephemeral container of the check's own (the
fixture's Alpine base, mounting the agent's `work` volume as uid 1000 under the namespace's `restricted` level): the
check used to `kubectl exec … tar` into the agent's container, and this image has no `tar`. Both images go through the
same container.

First run green on 2026-11-20 (k3s 1.34 on Docker Desktop, arm64): the probe proved the scan pods cut off, the scan
completed with no failed step and every plant found (one vulnerability, one secret, one SAST finding, seven IaC), in
1592 s, most of it building and importing the images. The Java agent's image passed the changed script the same
day with the same ten findings, so the shared path (the PEM entry it ignores, the ephemeral loader) is held for both. The nightly's `rust-agent-in-cluster` job runs it on the images
built at the night's commit, on the runner as the Java agent's run is.

**Not a drop-in yet with `agents.knownHosts`**: the chart copies the pinned host keys into the home with an init
container running `sh` from the agent's image, which this one does not have. To do before an installation pinning
its forges' keys moves to it.

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
- **A `pom.xml` in a charset the JDK knows but this reader does not decode** — `ISO-8859-2`, `Shift_JIS`… with
  bytes outside ASCII — is refused here ("maven", no version) and read by Java. UTF-8, UTF-16, ISO-8859-1,
  windows-1252 and ASCII are read as the JDK reads them, under every name it accepts; any other charset it knows
  is read when the document is ASCII. Its element names are checked against XML 1.0's fifth edition, where the
  JDK's tables are older: they differ only on names outside ASCII (`scanners::pom`).
- **A `package.json` name's length is counted in the bytes written**, escapes included, where Jackson counts the
  bytes it decoded: the two differ only for a name of 50,000 bytes written with `\u` escapes.
- **Java's `AnalysisBudget` is not reproduced**: it stops a pattern that reads more than 64 characters per
  character of a file, and the `regex` crate cannot backtrack. A file that exhausted it would be skipped by Java
  and read here; Java's own tests keep its patterns under six reads per character, and no case of
  `reference/workspace/` exhausts it.
- **A source file is opened `O_NONBLOCK`** as well as `O_NOFOLLOW`: a file replaced by a FIFO between the walk's
  look and the open would hold the Java worker until somebody writes to it.
- **The Kubernetes executor** (`crates/kubernetes`, decision 0045) differs from Java's in what is not ported yet (image
  targets) and in seven details. A bounded output whose `cat` fails after the probe found a regular file within its
  ceiling is a failure ("Its output could not be read back"), where Java reads `cat`'s nothing as the report and the
  SARIF reader then refuses it — the plugin is absent on both. A holder answering a size that is not a number fails the
  step, where Java's `Long.parseLong` throws out of the executor (`reference/kubernetes/collection.json` pins which
  answers do). The
  probe's configured target is read from `VECTISPIRE_AGENT_EXECUTOR_KUBERNETES_PROBETARGET`, the variable Spring binds
  `probe-target` from (the chart sets neither). A run whose future is dropped deletes its pod from a spawned task, as a
  Docker run removes its container. An operator's placement member that is not an object (`"affinity": []`) is
  replaced where the cache's node is added, where Java's cast throws. The archive written into a pod carries
  permission bits and no owner name (commons-compress writes the JVM's `user.name`); busybox's `tar` reads both alike.
- **JSON integers beyond 64 bits** in a scanner report would be read as doubles here, where Jackson
  keeps their low 32 bits. No scanner writes one.

- **An uploaded rule file whose last path component is not a plain name** (`..`, `/`, `x/.`) is
  refused with the "could not be written into the workspace" sentence; the Java side resolves it and
  fails on the write — or, for `/`, with a `NullPointerException`. Same outcome: the step fails.
- **The bundled rules' sweep compares with when this process materialised them**, not when it started
  (Rust has no portable process start time): later, which only ever keeps a leftover for the next sweep.

## The plugins: where this port and Java differ, and what the reference set found in Java

- **`OutputArchive` threw a `NullPointerException` on a PAX header naming a path but no size** (a `long`/`Long`
  ternary unboxing `null`): a well-formed archive was refused and the plugin absent. Fixed on the Java side in the
  same change (`Long.valueOf`), with a test; the reference set holds both sides to the fix.
- **The holder's `df` is multiplied as Java multiplies it, wrapping**: a value no bounded tmpfs can print reads as
  full on both sides (`measurements/`). Kept for parity; harmless, since the report is not believed either way.
- **Jackson's own words are not reproduced**: a SARIF document Jackson cannot read is refused on both sides with
  "not readable JSON:" and the parser's detail, which differs; a manifest the agent's mapper cannot read is absent
  with this port's sentence where Java writes Jackson's. The decisions are the same, pinned by the sets.
- **A Docker configuration's `auth` is decoded as `java.util.Base64` decodes it** (`pull_credentials::java_base64`),
  padding optional, and an unreadable configuration is refused in docker-java's words ("Failed to parse docker
  configuration file", or the JDK's base64 message, which docker-java lets through): the base64 crate's canonical
  padding refused an unpadded entry docker-java reads, and the sentences were this port's own. Found by
  `reference/kubernetes/registry-login.json`; fixed on 2026-11-20 for both executors.
- **Not ported**: docker-java's `registry.username`/`registry.password` properties, which override every entry of
  the Docker configuration (the Java agent sets none); `Character.digit`'s non-ASCII hexadecimal digits in a SARIF
  `%`-escape (Java decodes a full-width `%Ａ1`, this refuses it).

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
| **Dependencies: Syft + Grype** | `crates/scanners/src/dependencies.rs`, `vulnerability_database.rs`, `reference/dependencies/` | **Done** — their parsers hold to a reference set of real SBOM and match outputs (polyglot tree, empty tree, an exported Alpine image) and 29 edge cases; the database is downloaded under an `fcntl` lock shared with a Java agent and mounted read-only. Image export is `ContainerRunner::export_image` (a pull for the platform, then a save), since 2026-11-15 (task 2.10). |
| **IaC: Checkov** | `crates/scanners/src/iac.rs`, `reference/iac/` | **Done** — `iac::outcome` holds to `reference/iac/` (27 runs), and a real scan runs through the proxy. |
| **SAST: Semgrep** | `crates/scanners/src/sast.rs`, `reference/sast/` | **Done** — `sast::outcome` holds to `reference/sast/` (31 runs); `scanners::rules` places the bundled, operator and uploaded rules, and embeds the jar's. A real scan runs through the proxy. `scanners::output::parse_json` is shared, for the dependency stream. |
| **Workspace, census, API discovery** — *done* (branch `claude/rust-agent-census-api-156251`) | `crates/scanners/src/{census,manifest,api_discovery}.rs` and their readers (`source_files`, `walk`, `pom`, `properties`, `jackson_tree`), `reference/workspace/` | **Done** — `LanguageCensus`, `ProjectManifest` and `ApiDiscoveryScanner` hold to `reference/workspace/` (176 trees, hostile ones among them); the runner reads the manifest and the census before the containers and runs the discovery as a step (`runner::read_in_process`), the census kept for the plugins stream. 63/63 mutants killed (`security/mutants/agent-census-api.py`); two parsers fuzzed nightly (`project_manifest`, `api_discovery`). |
| **Plugins and bundled rules** — *done* 2026-11-19 (branch `claude/rust-agent-plugins-cosign-18a640`) | `crates/scanners/src/{plugins,sarif}.rs`, `crates/container/src/{bounded_output,run_with,pull_credentials}.rs`, `crates/domain/src/plugin_{manifest,signature,image}.rs`, `reference/plugins/` | Plugin steps, the bounded output holder (`ContainerRunner::run_with`, beside `run`), registry login and pull credentials, and `ImageSignatureVerifier` through the pinned cosign image — every decision held to `reference/plugins/`; a real keyless-signed plugin verified against Sigstore and run, another signer and an unsigned image refused, an overflowing output refused (`scanners/tests/plugins_through_the_proxy.rs`, Docker and the network); `security/mutants/agent-plugins.py`. **Left**: the built-in worker (`cp-app`) has no plugin source yet (every plugin absent, `PluginProvider.NONE`'s sentence). |
| **Kubernetes executor** — *done* (branch `claude/rust-agent-kubernetes-1d5565`) | `crates/kubernetes/**`, `crates/agent/src/executor.rs`; additions to `crates/container` (the `ContainerExecutor` seam, `ContainerRun.entrypoint`, `Mount.writable_bytes`) and the scanners' declared entrypoints | `VECTISPIRE_AGENT_EXECUTOR=kubernetes` chooses it at start, as Java does, with the chart's variables; the agent announces `kubernetes` and no image target. Held to `reference/kubernetes/` (all equal), and run on k3s 1.34 under the chart's Role by `crates/kubernetes/tests/on_k3s.rs` — Java's `KubernetesExecutorTest` and `ExecutorChoiceClusterTest`, and gitleaks, checkov, semgrep and syft each as a pod. Plugins run on it since 2026-11-20 (branch `rust/agent-k8s-plugins`): a bounded output is a memory `emptyDir` of its size, the plugin's to write and the holder's to read back and measure, and cosign's registry login is the mounted pull secret's entry (`VECTISPIRE_KUBERNETES_REGISTRY_CREDENTIALS`), copied in read-only, redacted from what the tool says, erased after — held to `reference/kubernetes/{pods,collection,registry-login}.json` and run on k3s. **In a cluster** since 2026-11-20 (branch `rust/agent-in-cluster`): this image installed by the chart scans through `AGENT=rust scripts/kubernetes-scan-check.sh` — the probe, every scanner as a pod, each plant found (k3s 1.34, arm64, 1592 s) — with the trust store's PEM form beside the PKCS12 (`agents.trustStore.pemKey`; the store alone refuses the start), run nightly by `rust-agent-in-cluster`; see "In a cluster, through the chart". **Not yet**: image targets (Java's §8 is not built either), the matcher against its real 3 GB database (the check moves a gigabyte of filler), and the chart's `agents.knownHosts`, whose init container runs `sh` from the agent's image, which this one does not have. |
| **Image and side-by-side conformance** — *built* (branch `rust/agent-image-conformance`); the two weeks have not started | `Dockerfile.agent`, `measure.sh`, `security/reproducible-image.sh`; CI's `rust-image` and `rust-image-arm64`; `../scripts/agent-conformance.sh`, `../scripts/compare-agent-runs.py`, `../ci/agent-conformance/accepted-differences.txt`, the nightly's `agent-conformance` | Built twice from nothing, one digest, on amd64 and on arm64 (each natively). A drop-in for the Java image: user 1000:1000, `HOME=/home/vectispire` writable by it, a `/tmp`, the same variables read, `/app/LICENSE`, `/app/NOTICE` and the third-party licences (2026-11-20, branch `rust/agent-compose-dropin`); on the Compose install the image swap is the whole change, `agent-work-dir` running the control plane's image. The nightly runs `scripts/composition-scan-check.sh` in agent mode through the Java agent and the Rust agent, both built at the commit, on a fixture planted identically, and compares what the control plane recorded of every scan. See "The image, and the side-by-side conformance" below for the rule that decides when `release.yml` signs it. |

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
| `cp-db` | the pools of both engines, transactions, the `Visibility`-gated query builder (a target's rows cannot be selected without it — compile-fail tests), checked queries with offline caches for both engines (`scripts/sqlx-prepare.sh check`, the one script for every crate with checked statements), the schema parity check that stands where `ddl-auto: validate` stood | the Java datasource and transaction semantics; a schema built by the real Flyway |
| `cp-http` | the Spring Security chain as thirteen tower layers in its order, problem documents, the route builder that cannot register a route without its requirement and its answer on visibility | the rc.3 control plane's answers, recorded (`crates/cp-http/tests/golden/`, captured by `capture.sh`); `trybuild` compile-fail cases |
| `cp-contract` | the contract kept identical: `openapi.json` of the 0.11.1 line embedded, routes against document in both directions with a list of routes not yet ported that only shrinks, schemas, published operation ids, the replay of the Java suite's recorded traffic | `ClientContractSpecTest`, `PublishedOperationIdsTest`; the recorder `vectispire-java/…/core/golden/` |
| `cp-arch-tests` | the boundaries as tests: the 28 modules' edge list, layering, cross-module SQL, `unsafe`, the agent's isolation, route authorization rules | `ModularityTest`, `ArchitectureTest`, `CrossModuleQueriesTest`, `RouteAuthorizationTest`, `AuthorizationCoverageTest` |
| `cp-outbound` | `PinnedHttpSender`, `OutboundUrlGuard`, `ReservedEndpoints`, the address classes | the Java classes, by `reference/outbound/` (202 URLs and 30 endpoints × 3 policies × 2 reservation sets, 114 reserved-endpoint readings, 68 addresses); local servers for the pin, the redirect, the ceiling, the deadline, a pinned CA over TLS |
| `cp-runtime` | the settings (108 properties under their Java names and defaults), `/run/secrets`, the logs, the audit mirror, the meters and the actuator's answers, graceful shutdown | `application.yaml` and the Java sources, read by `tests/java_parity.rs`; the actuator's bytes, recorded from rc.3 (`reference/actuator/`) |
| `cp-app` | the binary: `--check-config`, serve, stop gracefully — the HTTP stack and the database are not wired yet; the adapter that writes the audit module's mirror with `cp-runtime`'s file writer | the binary, run, by `tests/binary.rs` |
| `cp-audit` (Phase 1) | the audit log: the hash chain continued from the stored head under V66's one-row lock, the verification, the mirror comparison, the filtered page, the evidence bundle's lines | `reference/audit/` (`AuditChainReferenceSetTest`); the real Java `AuditLogService` on the same database, both ways and at once (`crates/cp-audit/oracle/check-oracle.sh`, needs JDK 25) |
| `cp-settings` (Phase 1) | the catalog (generated from Java's), each value's validation in Java's words, the store of `t_setting` and its two arbitrating writes, the first-install defaults, branding and the product version | `reference/settings/` (`SettingsReferenceSetTest`); both engines |
| `cp-access` (Phase 1) | accounts and passwords (Argon2id as `PasswordHasher` writes it, the lockout and governor rules); sessions, API keys, agents' keys and the SCIM token; the one `Role` (cp-http's) and its flags, `VisibilityService`, the row guards' 404s, four-eyes and who could approve; TOTP and the sign-in throttle's window and keys | `reference/accounts/`, `reference/credentials/`, `reference/sign-in/` (`vectispire-common`), `reference/access/` (`vectispire-core`); both engines; the published 0.11.0-rc.3 control plane on the same database (`tests/across_the_switch.rs`, `tests/against_java.rs`) |
| `cp-maintenance` (Phase 2) | the periodic jobs' port and their one global order, every Java slot reserved; the three turns (thirty seconds' initial delay, a fixed delay, a guard per cadence, a failing or panicking task ends its own run, not the turn); the composition check against Java's twenty-eight tasks with a deferred list that only shrinks; the one-shot jobs of `t_one_shot_job` | `reference/maintenance/` (`MaintenanceReferenceSetTest`); `MaintenanceJobsTest`'s cases; both engines, two instances claiming at once |
| `cp-platform` (Phase 1) | the settings screen's rules: what each reader sees of the catalog, every refusal of a save, the audit entry and its SOC signal — the modules it consults that are not ported yet are seams | `SettingsAdministrationService`'s sentences; both engines |

**The lists that only shrink are one file per module**, so that two or three module ports can run at once without
editing the same file:

| List | Files | Read by |
|---|---|---|
| routes of `openapi.json` not served yet | `crates/cp-contract/reference/not-yet-ported/<module>.txt` | each module's `tests/contract.rs` (`check_module`: its routes off the list, no other module's named), `cp-app`'s `tests/route_authorization.rs` (`check_partition`: the registry and the list are the document, exactly), `cp-contract replay-plan` and `summary` |
| recordings of the Java suite not replayed yet | `golden/deferred/<module>.txt`, `_composition.txt`, `_recording.txt` | `cp-contract replay-plan`, the golden replay (`crates/cp-agents/tests/golden.rs`) |
| what each module may use, and whether it is ported | `crates/cp-arch-tests/data/edges/<module>.toml`, `_workspace.toml` | `cp-arch-tests` |

Each list file carries its own `ceiling N` — the number of its lines, lowered in the commit that removes lines, a file
above or below it failing — so two ports never lower the same number; the totals (218 routes, 438 recordings on the
day of the split) are printed by `cp-contract summary` and `replay-plan`. The `README.md` of each directory says the
rules. The crate lists a new module used to join by hand are found instead: the workspace members (`crates/*`), the
replay tests (`replay-goldens.sh`: every `crates/*/tests/golden.rs` reading `VECTISPIRE_GOLDEN_DIR`), the crates with
checked queries (`sqlx-prepare.sh`: every `crates/*/.sqlx/`) and the mutation scripts (`security/mutants/[!_]*.py`).
`deny.toml`'s `wrappers` stay written by hand — who may link a driver or a server is a review decision — one crate per
line. What a port still edits in common is in `.claude/skills/port-module/SKILL.md` §5b.

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
- **`PinnedCa`** (`cp-outbound`) carries the form checks (PEM only, ≤ 16 384 characters, ≤ 8 certificates, nothing but certificates).
  The X.509 reading (CA flag, key usage, validity, the subject as BouncyCastle renders it) is `domain::pinned_ca`, written for the
  SIEM's collector CA (task 4.2) and held to `reference/siem/`; the door does not use it yet — the forge connections' port joins them.
- **The sender** sends `User-Agent: Vectispire`, does not ask for `gzip` and does not decode it, and honours no proxy.
- **One URL the guard reads differently:** `http://[fe80::1%eth0]/`, whose answer under the JDK depends on the host's interfaces — here it is
  unreadable everywhere, the safe side (the agent's `java_uri` port takes no scope id).

`cp-runtime`'s tests that name the control plane's own files (`tests/java_parity.rs`) read `../../../vectispire-java`: they run in a full checkout.
