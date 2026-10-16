#!/bin/sh
# Moves the contract the Rust port is held to: the served openapi.json and the list of operation ids
# a release publishes, both taken from a commit of the Java line — by hand, in a commit that says
# which and why. They are copies on purpose: a check that could be pointed at the working tree's
# file would be satisfied by editing that file.
#
#   reference/refresh.sh <commit-or-tag>      (run from anywhere inside the repository)
set -eu

ref="${1:?usage: refresh.sh <commit-or-tag> — the Java commit whose contract the port targets}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(git -C "$here" rev-parse --show-toplevel)"

git -C "$root" cat-file -e "$ref^{commit}"
git -C "$root" show "$ref:vectispire-angular/openapi.json" >"$here/openapi.json"
git -C "$root" show "$ref:vectispire-java/vectispire-core/src/test/resources/openapi/published-operation-ids.txt" \
  >"$here/published-operation-ids.txt"
printf 'contract taken from %s\n' "$(git -C "$root" rev-parse "$ref")"
printf 'now regenerate the allowlist with: cargo run -p vectispire-cp-contract -- allowlist-write\n'
