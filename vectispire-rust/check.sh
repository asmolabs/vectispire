#!/bin/sh
# Everything the Rust port of the agent passes before a commit — the Rust side of the quality gate.
#
# The suites that need a real server start throwaway containers named vs-rs-*: Docker is required,
# and its absence fails the run rather than skipping those suites (AGENTS.md, "Never skip silently").
# The reference sets are read as committed; regenerate them on purpose, never to make this pass
# (README.md, "The reference sets").
set -eu
cd "$(dirname "$0")"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny --locked check
