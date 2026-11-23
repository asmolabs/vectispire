#!/usr/bin/env bash
#
# **The Rust agent beside the Java one, on the same composition.** `composition-scan-check.sh` in agent
# mode, run twice against the control plane built at the commit — once through the Java agent's image,
# which ships, once through the Rust agent's — on a fixture planted identically (the same token, the same
# commit, byte for byte), and what the control plane recorded of each scan compared by
# `compare-agent-runs.py`: status, failed steps and their sentences, absent vs empty, plugins, every finding
# and every issue's fingerprint. Any difference not listed with its reason in
# `ci/agent-conformance/accepted-differences.txt` fails it, and so does either run failing its own check.
#
# Why: the Rust agent is held to the Java one parser by parser (vectispire-rust/reference/), and that says
# nothing of the composition — the clone, the workspace handed to the daemon, the scanners' mounts and
# users, the steps' wiring, what reaches the wire. This is the one check that asks both agents the same
# questions through the product. `release.yml` signs the Rust image only after two weeks of nightly runs
# of this with no difference (vectispire-rust/README.md).
#
# Usage (from the repository root; Docker required, about twice the composition check's time):
#   CONTROL_PLANE_IMAGE=vectispire:x JAVA_AGENT_IMAGE=vectispire-agent:x RUST_AGENT_IMAGE=vs-rs-agent:x \
#     scripts/agent-conformance.sh [output directory]
# The output directory keeps both runs' answers (`java/`, `rust/`) and the comparison; a fresh temporary
# one when none is named.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"
: "${CONTROL_PLANE_IMAGE:?the control plane built at the commit}"
: "${JAVA_AGENT_IMAGE:?the Java agent built at the commit}"
: "${RUST_AGENT_IMAGE:?the Rust agent built at the commit}"
out="${1:-$(mktemp -d "${TMPDIR:-/tmp}/vs-agent-conformance.XXXXXX")}"
mkdir -p "$out/java" "$out/rust"
rm -f "$out/java/"*.json "$out/rust/"*.json

# One token for both fixtures: a secret's fingerprint is read off the value found.
token="ghp_$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-36)"
run() { # name, agent image
  echo "══ the $1 agent ($2)"
  if MODE=agent CONTROL_PLANE_IMAGE="$CONTROL_PLANE_IMAGE" AGENT_IMAGE="$2" \
       PROJECT="vectispire-conformance-$1" DETAIL_DIR="$out/$1" FIXTURE_TOKEN="$token" CONTAINER_LOG="$out/$1.containers.log" \
       "$root/scripts/composition-scan-check.sh" 2>&1 | tee "$out/$1.log"; then
    echo "passed" > "$out/$1.status"
  else
    echo "failed" > "$out/$1.status"
  fi
}
run java "$JAVA_AGENT_IMAGE"
run rust "$RUST_AGENT_IMAGE"

echo "══ comparing what the control plane recorded of each scan (reference: the Java agent)"
status=0
python3 "$root/scripts/compare-agent-runs.py" "$out/java" "$out/rust" \
  "$root/ci/agent-conformance/accepted-differences.txt" | tee "$out/comparison.txt" || status=1
for side in java rust; do
  if [ "$(cat "$out/$side.status")" != passed ]; then
    echo "✗ the $side agent's run failed its own check (log: $out/$side.log): what it kept is compared above"
    status=1
  fi
done
echo "answers and logs kept in $out"
exit "$status"
