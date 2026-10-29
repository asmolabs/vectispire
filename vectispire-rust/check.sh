#!/bin/sh
# Everything the Rust port of the agent passes before a commit — the Rust side of the quality gate.
#
# The suites that need a real server start throwaway containers named vs-rs-*: Docker is required,
# and its absence fails the run rather than skipping those suites (AGENTS.md, "Never skip silently").
# The reference sets are read as committed; regenerate them on purpose, never to make this pass
# (README.md, "The reference sets").
#
# **Both engines, unless told otherwise.** `VECTISPIRE_TEST_ENGINES=mysql ./check.sh` is the gate a port's pull
# request may run (decided 2026-10-29): every suite on a database runs on MySQL, each PostgreSQL case says it was
# left out, and the nightly runs both. The code is still written for both engines; a misspelt value fails the tests.
set -eu
cd "$(dirname "$0")"
if [ -n "${VECTISPIRE_TEST_ENGINES+set}" ]; then
  echo "check.sh: VECTISPIRE_TEST_ENGINES=$VECTISPIRE_TEST_ENGINES — the engines it leaves out are the nightly's"
fi
# cargo-deny and cargo-vet at the versions CI runs, built once per machine (security/install-tools.sh):
# a worktree without them used to stop the gate halfway, or be run without its last steps.
./security/install-tools.sh cargo-deny cargo-vet
PATH="$(./security/install-tools.sh --bin):$PATH"
export PATH

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny --locked check

# The security checks (security/README.md), each also a step of CI's `rust` job: `unsafe` in its one
# file, the panicking lints held to their ceilings, every crate audited or exempted by name, and the
# workspace's own semgrep rules. `cargo vet --locked` reads the audits imported in supply-chain/
# rather than fetching them, so a run is the same tomorrow; `cargo vet` (unlocked) refreshes them.
./security/check-unsafe.sh
./security/lint-ceilings.sh
cargo vet --locked
./security/semgrep.sh

# Each mutation script's guards must still be found in the sources, exactly once. This runs no mutant
# (security/mutants/README.md): it keeps the lists from rotting silently when the code they break moves,
# so that the next full run still means something.
for script in security/mutants/p*.py; do python3 "$script" --check; done
