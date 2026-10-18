#!/bin/sh
# Replays the Java suite's recorded traffic against the Rust routes that are served (MIGRATION.md §2, "Golden
# replay"). Records the suite at this commit into <dir> first, unless <dir> already holds a recording of it
# (record-goldens.sh writes one; CI passes the one it just made), then:
#
#   1. `cp-contract replay-plan <dir>`: every recording read, and every one of a route not served, or outside the
#      contract, covered by a line of golden/deferred.txt — no database needed;
#   2. each served module's replay test on MySQL 9.4 and PostgreSQL 17 (ignored by a plain `cargo test`, since it
#      needs the recording): every recording of a served route replays green on both engines, or is listed.
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
# One line per module whose routes are served; a module that ports routes adds its own.
VECTISPIRE_GOLDEN_DIR="$dir" cargo test --locked -p vectispire-cp-targets --test golden -- --ignored --nocapture
