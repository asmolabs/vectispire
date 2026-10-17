#!/bin/sh
# Records the Java suite's HTTP traffic at this commit, into <dir>: one file per request of every HTTP test,
# normalised (vectispire-java/…/core/golden/README.md). It is the oracle the Rust control plane is replayed
# against, and it is generated rather than committed: 66 MB, 7,000 files, and any change to a response would
# rewrite hundreds of them.
#
# The suite is run with the recorder on, and **two tests are expected to fail under it** (they pass without it:
# reference/recording-known-failures.txt says which and why). The run is accepted only if the failures are exactly
# those — a third failure is a regression, and one of the two passing is the list to shrink. A run that ran
# fewer tests than the suite holds, or none, fails: a recording of nothing would pass whatever the suite did.
#
#   crates/cp-contract/scripts/record-goldens.sh <dir>        (Docker and a JDK 25 are required; nothing skips)
set -eu
dir="${1:?usage: record-goldens.sh <dir to record into>}"
here="$(cd "$(dirname "$0")" && pwd)"
known="$here/../reference/recording-known-failures.txt"
java="$(cd "$here/../../../../vectispire-java" && pwd)"
command -v docker >/dev/null || { echo "record-goldens.sh: Docker is required" >&2; exit 1; }
"${JAVA_HOME:+$JAVA_HOME/bin/}java" -version >/dev/null 2>&1 || { echo "record-goldens.sh: a JDK 25 is required" >&2; exit 1; }

rm -rf "$dir"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
cd "$java"
status=0
TESTCONTAINERS_REUSE_ENABLE=false ./gradlew :vectispire-core:cleanTest :vectispire-core:test \
  -Pvectispire.golden.dir="$dir" --dependency-verification=strict --console=plain || status=$?

python3 - "$java/vectispire-core/build/test-results/test" "$known" "$dir" "$status" <<'PY'
import glob, os, sys
import xml.etree.ElementTree as ET

results, known_file, directory, status = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
ran, failed = 0, set()
for path in glob.glob(os.path.join(results, "*.xml")):
    for case in ET.parse(path).getroot().iter("testcase"):
        ran += 1
        if case.find("failure") is not None or case.find("error") is not None:
            failed.add(f"{case.get('classname')} | {case.get('name')}")
known = {
    line.strip()
    for line in open(known_file, encoding="utf-8")
    if line.strip() and not line.startswith("#")
}
files = sum(1 for _, _, names in os.walk(directory) for name in names if name.endswith(".json"))
print(f"{ran} tests ran, {len(failed)} failed (expected {len(known)}); {files} recorded files in {directory}")
problems = []
if ran < 2000:
    problems.append(f"only {ran} tests ran: the suite holds more than 2,000, so the recording read too little")
if files < 5000:
    problems.append(f"only {files} files were recorded: the recorder was not on, or recorded too little")
for name in sorted(failed - known):
    problems.append(f"fails under the recorder and is not expected to: {name}")
for name in sorted(known - failed):
    problems.append(f"is expected to fail under the recorder and does not — remove it from {known_file}: {name}")
if problems:
    print("\n".join(f"::error::{p}" for p in problems))
    sys.exit(1)
PY
