#!/bin/sh
# Semgrep over the Rust workspace with its own rules (security/semgrep/rust.yml), at the digest
# ScannerImages pins — the version that scans the targets scans the agent. Offline (`--metrics=off`,
# no registry ruleset): the rules are the file, nothing fetched. A run that read no Rust file fails.
set -eu
cd "$(dirname "$0")/.."
IMAGE=semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8

docker run --rm --network none -v "$PWD:/src:ro" -w /src "$IMAGE" \
  semgrep scan --quiet --metrics=off --disable-version-check --error --config security/semgrep/rust.yml \
  --exclude target --json --output /dev/stdout . > "${TMPDIR:-/tmp}/vs-rs-semgrep.json" || status=$?
status=${status:-0}
python3 - "${TMPDIR:-/tmp}/vs-rs-semgrep.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
scanned = [p for p in report.get("paths", {}).get("scanned", []) if p.endswith(".rs")]
for r in report.get("results", []):
    print(f"{r['path']}:{r['start']['line']}: {r['check_id']}: {r['extra']['message']}")
errors = report.get("errors", [])
for e in errors:
    print("semgrep error:", e.get("message", e)[:300])
print(f"{len(scanned)} Rust files scanned, {len(report.get('results', []))} finding(s), {len(errors)} error(s)")
sys.exit(1 if not scanned or errors else 0)
PY
exit "$status"
