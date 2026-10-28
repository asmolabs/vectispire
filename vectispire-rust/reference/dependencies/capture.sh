#!/bin/sh
# Captures the real outputs of the dependency reference set — sboms/0[1-3]-*.json and matches/0[1-3]-*.json
# — from the pinned Syft and Grype images, run the way the agent's runner runs a scanner: read-only root,
# a tmpfs scratch space, no network, as the caller's user, the runner's environment.
#
#   reference/dependencies/capture.sh <grype database directory>
#
# The database directory is a Grype cache (`<dir>/6/vulnerability.db`), from `grype db update` or a
# Vectispire host's `generations/<name>`; the committed outputs were matched against the database
# published on 2026-10-16. A different database gives different matches: run it on purpose, then
# regenerate the Java side's answers (`./gradlew :vectispire-common:test --tests '*ReferenceSetTest*'
# -Dvectispire.rust.reference.write=true`) and run `vectispire-rust/check.sh`.
#
# The fixture trees are committed as `*.fixture` so that no forge reads a lock file of known-vulnerable
# versions as this repository's dependencies; they are copied under their real names into a scratch
# directory here.
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <grype database directory>" >&2; exit 2; }
database=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)

SYFT=anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026
GRYPE=anchore/grype@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db
# alpine 3.12.0, the multi-architecture index; exported for linux/amd64, as DEFAULT_PLATFORM audits.
IMAGE=alpine:3.12.0@sha256:185518070891758909c9f839cf4ca393ee977ac378609f700f60a771a2dfe321

scratch=$(mktemp -d "${TMPDIR:-/tmp}/vs-rs-capture-XXXXXX")
trap 'rm -rf "$scratch"' EXIT

scan() {
  name=$1
  shift
  docker run --rm --name "vs-rs-capture-$name-$$" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,noexec,nosuid,mode=1777,size=512m --tmpfs /home/scanner:rw,noexec,nosuid,mode=1777,size=512m \
    -e HOME=/home/scanner -e TMPDIR=/tmp -e XDG_CACHE_HOME=/home/scanner/.cache -e GRYPE_DB_CACHE_DIR=/cache \
    -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false "$@"
}

# The SBOM goes to the matcher compact, as `JsonNode.toString()` writes it.
compact() {
  python3 -c 'import json,sys; sys.stdout.write(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":")))' "$1"
}

match() {
  label=$1
  mkdir -p "$scratch/match-$label"
  compact "$here/sboms/$2" > "$scratch/match-$label/sbom.json"
  chmod -R a+rX "$scratch/match-$label"
  scan "grype-$label" -v "$scratch/match-$label:/repo:ro" -v "$database:/cache:ro" "$GRYPE" sbom:/repo/sbom.json -o json \
    > "$here/matches/$2"
}

for tree in polyglot clean; do
  mkdir -p "$scratch/$tree/source"
  (cd "$here/fixtures/$tree" && find . -type f -name '*.fixture') | while read -r file; do
    target="$scratch/$tree/source/${file%.fixture}"
    mkdir -p "$(dirname "$target")"
    cp "$here/fixtures/$tree/$file" "$target"
  done
done
chmod -R a+rX "$scratch"

scan syft-polyglot -v "$scratch/polyglot:/repo:ro" "$SYFT" dir:/repo/source -o json > "$here/sboms/01-polyglot.json"
scan syft-clean -v "$scratch/clean:/repo:ro" "$SYFT" dir:/repo/source -o json > "$here/sboms/02-clean.json"

mkdir -p "$scratch/image"
docker pull -q --platform linux/amd64 "$IMAGE" > /dev/null
docker save --platform linux/amd64 "$IMAGE" -o "$scratch/image/image.tar"
chmod a+r "$scratch/image/image.tar"
scan syft-image -v "$scratch/image:/repo:ro" "$SYFT" docker-archive:/repo/image.tar -o json > "$here/sboms/03-alpine-image.json"

match polyglot 01-polyglot.json
match clean 02-clean.json
match image 03-alpine-image.json
echo "captured; now regenerate the Java side's answers and run vectispire-rust/check.sh"
