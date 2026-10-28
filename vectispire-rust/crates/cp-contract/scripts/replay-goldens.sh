#!/bin/sh
# Replays the Java suite's recorded traffic against the Rust routes that are served (MIGRATION.md §2, "Golden
# replay"). Records the suite at this commit into <dir> first, unless <dir> already holds a recording of it
# (record-goldens.sh writes one; CI passes the one it just made), then:
#
#   1. `cp-contract replay-plan <dir>`: every recording read, and every one of a route not served, or outside the
#      contract, covered by a line of golden/deferred/ — no database needed;
#   2. each replay test on MySQL 9.4 and PostgreSQL 17 (ignored by a plain `cargo test`, since it needs the
#      recording): every recording of a served route replays green on both engines, or is listed. **The replay tests
#      are found, not listed**: every `crates/*/tests/golden.rs` that reads VECTISPIRE_GOLDEN_DIR, so that a module
#      whose replay lives in its own crate adds no line here. Today there is one, cp-agents', which composes every
#      served module (`targets`, `scanning` and `agents` answer through one another, 2.9; Phase 3's beside them).
#
#   crates/cp-contract/scripts/replay-goldens.sh <dir> [--record]     (Docker and, to record, a JDK 25 are required)
set -eu
dir="${1:?usage: replay-goldens.sh <recording dir> [--record]}"
here="$(cd "$(dirname "$0")" && pwd)"
workspace="$(cd "$here/../../.." && pwd)"
if [ "${2:-}" = "--record" ] || [ ! -f "$dir/manifest.json" ]; then
  "$here/record-goldens.sh" "$dir"
fi
dir="$(cd "$dir" && pwd)"
cd "$workspace"
cargo run --locked -q -p vectispire-cp-contract -- replay-plan "$dir"
replays=0
for test in crates/*/tests/golden.rs; do
  grep -q VECTISPIRE_GOLDEN_DIR "$test" || continue
  crate="vectispire-$(basename "$(dirname "$(dirname "$test")")")"
  echo "replaying in $crate"
  VECTISPIRE_GOLDEN_DIR="$dir" cargo test --locked -p "$crate" --test golden -- --ignored --nocapture
  replays=$((replays + 1))
done
# A glob that matched nothing would replay nothing and pass.
[ "$replays" -gt 0 ] || { echo "no crates/*/tests/golden.rs reads VECTISPIRE_GOLDEN_DIR: nothing was replayed" >&2; exit 1; }
