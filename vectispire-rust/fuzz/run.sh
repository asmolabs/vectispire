#!/bin/sh
# Every fuzz target, each for a time budget, from a corpus seeded with the reference sets — the inputs
# the Java and Rust parsers are already known to agree on, so the fuzzer starts from real shapes.
#
# A crash, a failed assertion, a timeout or a leak fails the run, and the input that did it is left in
# fuzz/artifacts/<target>/ (nightly.yml uploads it). Reproduce with `cargo fuzz run <target> <file>`.
# Usage: fuzz/run.sh [seconds per target, 60 by default] [target …]
set -eu
cd "$(dirname "$0")"
budget=${1:-60}
[ $# -gt 0 ] && shift
targets=${*:-$(cargo fuzz list)}
[ -n "$targets" ] || { echo "no fuzz target listed: the run would have fuzzed nothing"; exit 1; }

corpus=${FUZZ_CORPUS:-$(mktemp -d "${TMPDIR:-/tmp}/vs-rs-fuzz.XXXXXX")}
seed() {  # seed <target> <file>…: one corpus entry per file, or per element of a JSON array of strings
  mkdir -p "$corpus/$1"; target=$1; shift
  python3 - "$corpus/$target" "$@" <<'PY'
import hashlib, json, os, sys
out = sys.argv[1]
def put(data):
    open(os.path.join(out, hashlib.sha1(data).hexdigest()), "wb").write(data)
for path in sys.argv[2:]:
    raw = open(path, "rb").read()
    put(raw)
    try:
        value = json.loads(raw)
    except ValueError:
        continue
    items = value if isinstance(value, list) else list(value.values()) if isinstance(value, dict) else []
    for item in items:
        if isinstance(item, str):
            put(item.encode())
        elif isinstance(item, dict) and isinstance(item.get("raw"), str):  # failure_scrub: raw, NUL, a secret
            secrets = [s for s in item.get("secrets") or [] if isinstance(s, str)]
            put((item["raw"] + "\0" + (secrets[0] if secrets else "")).encode())
PY
}
seed repository_url ../reference/repository-url/inputs.json
seed secrets_report ../reference/secrets/reports/*
seed sealed_envelope ../reference/crypto/*.json
seed signatures ../reference/crypto/*.json
seed known_hosts ../reference/repository-url/inputs.json
seed sast_report ../reference/sast/runs/*.stdout
seed iac_report ../reference/iac/runs/*.stdout
seed grype_matches ../reference/dependencies/matches/*.json
seed syft_sbom ../reference/dependencies/sboms/*.json
seed failure_scrub ../reference/failure-reason/inputs.json
seed https_location ../reference/repository-url/inputs.json

failed=""
for target in $targets; do
  mkdir -p "$corpus/$target"
  echo "== $target, ${budget}s, $(find "$corpus/$target" -type f | wc -l | tr -d ' ') seed(s)"
  # The status is the fuzzer's, not a pipe's: the log goes to a file and is shown after.
  status=0
  cargo fuzz run -O "$target" "$corpus/$target" -- \
    -max_total_time="$budget" -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 \
    > "$corpus/$target.log" 2>&1 || status=$?
  tail -25 "$corpus/$target.log"
  [ "$status" -eq 0 ] || failed="$failed $target"
done
if [ -n "$failed" ]; then echo "fuzzing found a failure in:$failed (inputs in fuzz/artifacts/)"; exit 1; fi
echo "every target ran ${budget}s without a failure"
