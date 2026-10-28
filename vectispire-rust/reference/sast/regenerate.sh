#!/bin/sh
# Regenerates the real runs of the SAST reference set (runs/01- to 06-): the pinned semgrep image with
# the bundled rule — read from bundled-rules/, the jar's bytes — and an operator rule set, as the
# agent runs it. The edges (07- on) are written by hand and kept as they are.
#
# **Not deterministic**: the tools print timings and, for checkov, its checks in no fixed order. A
# regeneration therefore changes these files, and the Java answers must be rewritten after it.
#
# Then regenerate the Java answers and make the Rust port agree (README.md, "The reference sets"):
#   ./gradlew :vectispire-common:test --tests '*SastReferenceSetTest*' -Dvectispire.rust.reference.write=true
set -eu
cd "$(dirname "$0")"
image=$(sed -n 's/.*"\(semgrep\/semgrep@sha256:[0-9a-f]*\)".*/\1/p' ../../crates/scanners/src/images.rs)
[ -n "$image" ] || { echo "no semgrep pin in images.rs" >&2; exit 1; }
root=$(mktemp -d "${TMPDIR:-/tmp}/vs-rs-sast.XXXXXX")
trap 'rm -rf "$root"' EXIT
bundled=$PWD/bundled-rules
mk() { mkdir -p "$(dirname "$1")"; cat > "$1"; }
ws() { mkdir -p "$root/$1/rules"; cp -R "$bundled/semgrep" "$root/$1/rules/"; }

ws eval
mk "$root/eval/source/app.py" <<'PY'
import sys


def handle(expression):
    return eval(expression)


print(eval("1 + 1"))
print(handle(sys.argv[1]))
PY

ws operator
mk "$root/operator/rules/semgrep/operator/rule-0001.yaml" <<'YAML'
rules:
  - id: example.python.subprocess-shell
    languages: [python]
    severity: WARNING
    metadata:
      category: security
      owasp: "A03:2021 - Injection"
      confidence: MEDIUM
    message: A shell command built from input.
    pattern: subprocess.call(..., shell=True)
  - id: example.python.both-editions
    languages: [python]
    severity: ERROR
    metadata:
      owasp:
        - A01:2017 - Injection
        - A03:2021 - Injection
    message: Two editions named; only 2021 counts.
    pattern: os.system(...)
  - id: example.python.only-2017
    languages: [python]
    severity: INFO
    metadata:
      category: security
      owasp:
        - A06:2017 - Security Misconfiguration
    message: Only the 2017 edition, which places nothing.
    pattern: pickle.loads(...)
  - id: example.python.print-debug
    languages: [python]
    severity: INFO
    metadata:
      category: maintainability
    message: A debug print.
    pattern: print("debug", ...)
  - id: example.js.document-write
    languages: [javascript]
    severity: WARNING
    metadata:
      category: security
      owasp: [ "not an owasp tag", "A10:2021 - SSRF" ]
      confidence: LOW
    message: document.write with a value.
    pattern: document.write($X)
YAML
mk "$root/operator/source/tool.py" <<'PY'
import os
import pickle
import subprocess


def run(command, blob):
    subprocess.call(command, shell=True)
    os.system(command)
    print("debug", command)
    return pickle.loads(blob)
PY
mk "$root/operator/source/web/page.js" <<'JS'
function show(value) {
  document.write(value);
}
JS

ws ignored
mk "$root/ignored/source/.semgrepignore" <<'IGN'
*
IGN
mk "$root/ignored/source/app.py" <<'PY'
print(eval(input()))
PY

ws no-python
mk "$root/no-python/source/README.md" <<'MD'
No file any rule's language reads.
MD

ws invalid
mk "$root/invalid/rules/semgrep/operator/rule-0001.yaml" <<'YAML'
rules:
  - id: example.broken
    languages: [python]
    severity: ERROR
    message: Missing its pattern.
YAML
mk "$root/invalid/source/app.py" <<'PY'
print(eval(input()))
PY

ws sub-path
mk "$root/sub-path/source/service/handler.py" <<'PY'
def handle(text):
    return eval(text)
PY
mk "$root/sub-path/source/other/skip.py" <<'PY'
eval(open("x").read())
PY

# The scan as the agent runs it: no network, read-only root, no capability, the workspace read-only,
# as the workspace's owner. What the container prints is kept as the run's stdout and stderr.
scan() {
  ws=$1; image=$2; out=$3; shift 3
  set +e
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 512 --memory 2g --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,noexec,nosuid,mode=1777,size=512m \
    --tmpfs /home/scanner:rw,noexec,nosuid,mode=1777,size=512m \
    -e HOME=/home/scanner -e TMPDIR=/tmp -e XDG_CACHE_HOME=/home/scanner/.cache \
    -v "$ws:/repo:ro" "$image" "$@" >"$out.stdout" 2>/dev/null
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then printf 'exit=%s\n' "$code" >>"$out.case"; fi
}

semgrep() {
  ws=$1; out=$2; target=$3
  scan "$ws" "$image" "$out" semgrep scan --config=/repo/rules/semgrep --no-rewrite-rule-ids --no-git-ignore \
    --json --metrics=off --disable-version-check --quiet --timeout=30 --timeout-threshold=3 \
    --max-target-bytes=1000000 --max-memory=1500 --jobs=2 "$target"
}
for pair in eval:01-bundled-rule operator:02-operator-rules ignored:03-semgrepignore-everything \
  no-python:04-no-file-in-a-rule-language invalid:05-invalid-rule; do
  tree=${pair%%:*}; name=${pair#*:}
  rm -f "runs/$name.case"
  semgrep "$root/$tree" "runs/$name" /repo/source
done
: >runs/05-invalid-rule.stderr
printf 'subPath=service\n' >runs/06-sub-path.case
semgrep "$root/sub-path" runs/06-sub-path /repo/source/service
