# The Rust code's security checks

What every change under `vectispire-rust/` passes, where it runs, and what each one is for. They are the
steps of CI's `rust` and `rust-image` jobs (`.github/workflows/ci.yml`) and of the nightly `rust-fuzz`
job (`nightly.yml`). `../check.sh` runs the per-push ones locally, in the same order.

Each check was broken on purpose once, and turned red, before it was trusted. The "proved by" column
says how, so that the next person can repeat it rather than believe it.

| Check | What it refuses | Where | Proved by |
|---|---|---|---|
| `cargo fmt --check` | unformatted code | `rust` | — |
| clippy, `-D warnings`, with the lints `Cargo.toml` denies | `unwrap`/`expect` in shipped code, `print!`/`eprint!`, `dbg!`, `todo!`, `unimplemented!`, `mem::forget`, an `unsafe` block without `// SAFETY:` | `rust` | a `println!` added to a library crate |
| `check-unsafe.sh` | `unsafe` — a block, function, impl, trait, extern block or attribute — or an `allow(unsafe_code)` anywhere but `crates/git/src/init.rs` | `rust` | an `unsafe {}` added to `crates/domain` |
| `lint-ceilings.sh` | a new indexing, slicing, unchecked arithmetic or truncating cast in shipped code, beyond the counts in `lint-ceilings.txt` — one count for the agent's crates and one for the control plane's (`cp-*`, `migrate`) | `rust` | one more `bytes[0]` in either scope |
| `cargo test`, Docker required | every behaviour pinned so far, including the reference sets and `crates/agent/tests/isolation.rs` (no database client, server framework or test support in the agent's graph — decision 0003) | `rust` | the crates' own mutation checks (README.md) |
| `cargo deny check` (`../deny.toml`) | an advisory (vulnerable, unsound, unmaintained, yanked), a banned crate, a licence not listed, a registry or git source other than crates.io, a new duplicate version, **a build script not listed**, an executable inside a crate's source | `rust` | a build-script crate dropped from the list; a duplicate unlisted; a licence removed |
| `cargo vet --locked` (`../supply-chain/`) | a crate neither audited by an imported set (Mozilla, Google, Bytecode Alliance, Zcash, ISRG) nor exempted by name and version | `rust` | a new dependency added |
| `semgrep.sh` (`semgrep/rust.yml`) | certificate checks switched off, an HTTP client built outside `crates/tls`, a redirect followed, a program started, a `Secret` exposed in a log line, a weak or seeded RNG | `rust` | `danger_accept_invalid_certs(true)` added |
| gitleaks | a credential in the history — the `secrets` job already reads every commit, `vectispire-rust/` included | `secrets` | the port's own fixtures, rewritten after it flagged three |
| `reproducible-image.sh` | an image that differs between two builds of one commit from nothing | `rust-image` | a build-time value written into the image |
| syft + grype, at `ScannerImages`' digests | a fixable high or critical in the image; a scan that saw too few crates in the binary (cargo-auditable's list missing) | `rust-image` | the image built without `cargo auditable` |
| cargo-cyclonedx | — (an artifact: the CycloneDX SBOM of the agent's resolved crates) | `rust-image` | — |
| checkov | the Dockerfile's policy (non-root, pinned base, no `latest`…), by name as well as in the directory walk | `dockerfile-policy` | `USER 1000:1000` removed |
| `cargo fuzz` (`../fuzz/`) | a crash, a failed assertion, a timeout or a leak in the URL, the secrets, SAST, IaC, Grype and Syft readers, the failure reason's scrub, a `Location` header, and the sealed envelope, signature and known-hosts readers | nightly `rust-fuzz` | a panic planted behind an input prefix |
| Miri | undefined behaviour in `domain`, `crypto` and `scanners` and the dependencies they call | nightly `rust-fuzz` | — |

## Choices, and what was not done

- **Denied, not forbidden, `unsafe`.** A forbidden lint cannot be allowed for the two libgit2 calls;
  `check-unsafe.sh` is what makes the deny a forbid everywhere else.
- **Indexing, slicing and arithmetic are counted, not denied** (`lint-ceilings.txt`). The URL and
  known-hosts parsers use them on bounds they check first; denying them would mean rewriting those
  parsers outside the stream that owns them. Their ceilings only go down, release builds panic on
  overflow (`overflow-checks = true`), and both parsers are fuzzed every night. The ceilings are per scope
  because one total would let either side grow into the other's slack; the agent's rose from 29/7/44/9 to
  34/11/75/10 when its protocol, dependency and IaC/SAST streams landed after the first count (the
  control plane's started at 50/63/118/3 on the day its crates joined).
- **No cargo-audit.** It reads the same RustSec database `cargo deny`'s advisories check reads, which
  also refuses unmaintained and yanked crates; the shipped binary is audited from what it carries, by
  grype on the image.
- **cargo-vet starts with exemptions.** 55 crates are audited by an imported set, 314 are exempted at
  their current version (225 before the control plane's crates joined the workspace, 311 before `cp-access` brought
  Argon2 — `argon2`, `blake2`, `password-hash`, each exempted with its reason): the policy is that the list does not grow by accident — a new crate or a new
  version fails until it is audited or exempted in a reviewed diff. `cargo vet` without `--locked`
  refreshes the imported audits; `cargo vet prune` drops the exemptions they now cover.
- **The fuzz targets cover the readers of untrusted input that exist.** Eleven: the URL, the secrets, SAST, IaC,
  Grype and Syft readers, the failure reason's scrub, a `Location` header (the one thing an HTTPS forge says that
  the clone reads for itself), the sealed envelope, the signatures and the known-hosts reader. The control
  plane's own readers (a request body, the contract's JSON reader) get theirs when they are written; a
  parser of untrusted input is a target in the same diff (one file in `../fuzz/fuzz_targets/`, a `[[bin]]` in
  `../fuzz/Cargo.toml`, a seed line in `../fuzz/run.sh`).
- **Miri skips `git`, `container`, `protocol` and `agent`**: they call libgit2, sockets or the system,
  which Miri cannot run.
- **The fuzz workspace is outside deny and vet.** It is never built into anything shipped, and holds
  `libfuzzer-sys` only.
