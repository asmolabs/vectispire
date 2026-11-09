#!/usr/bin/env bash
#
# The API contract against the last release: fails on a change that breaks a client of it.
#
# **Why this exists beside `ClientContractSpecTest`.** That test keeps `openapi.json` equal to the
# document the application serves; regenerating the file makes it pass again. It detects a change,
# it does not refuse a breaking one — decision 0043 §1 names this diff as the check that does. A
# response field renamed on the server breaks the interface and every integration without touching
# a front-end file, so `e2e` does not run on it either; this is the one place it is caught on push.
#
# **What it compares.** `vectispire-angular/openapi.json` at HEAD — the served document, by that
# test — against the same file at the newest `v*` tag reachable from HEAD, release candidates
# included (`versionsort.suffix=-rc` puts `v0.11.0` after `v0.11.0-rc.3`, and a tag on a line HEAD
# does not descend from is not what HEAD's users run).
#
# **With what.** oasdiff, at a digest: the rules for what breaks a client of an OpenAPI document are
# many (some 750 checks) and a hand-written diff would cover the half its author thought of. Its
# defaults are tuned for documents that declare what springdoc does not, so seven of its checks are
# raised to errors below and one lowered, each with the reason.
#
# **The escape hatch is a reviewed file, never a flag.** `ci/openapi/accepted-breaks.txt` lists an
# intentional break with the tag it breaks against and why. An entry for another tag, or one that
# matches no break any more, fails the run: the list only shrinks back to empty at each release.
#
# Usage:
#   ci/openapi/compat.sh                    # against the newest reachable v* tag
#   BASE_TAG=v0.10.0 ci/openapi/compat.sh   # against a named one

set -euo pipefail

# v1.33.0. A tag is mutable; the digest is the tool that ran. Resolve the next one with
# `docker buildx imagetools inspect tufin/oasdiff:<version>` and replace both.
OASDIFF_IMAGE="tufin/oasdiff@sha256:6263a96dd2ef0726c54e21fea9b8e1607eac4841add0079324b424c1f52b819c"
SPEC="vectispire-angular/openapi.json"
ACCEPTED="ci/openapi/accepted-breaks.txt"

fail() { printf '\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"

BASE_TAG="${BASE_TAG:-$(git -c versionsort.suffix=-rc tag -l 'v*' --merged HEAD --sort=-v:refname | head -n 1)}"
# No tag is not "nothing to compare": it is a shallow clone or a fetch without tags, and a green
# run over it would have read nothing.
[ -n "$BASE_TAG" ] || fail "no v* tag reachable from HEAD — the checkout needs its history and tags (fetch-depth: 0)"
[ -f "$ACCEPTED" ] || fail "$ACCEPTED is missing — it is the only way to accept a break, and an empty one accepts none"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 0755 "$WORK"

git show "$BASE_TAG:$SPEC" > "$WORK/base.json" 2>/dev/null \
  || fail "$SPEC does not exist at $BASE_TAG"
cp "$SPEC" "$WORK/head.json"
chmod 0644 "$WORK/base.json" "$WORK/head.json"

# oasdiff reads no comment in this file and refuses an unknown rule id, so the reasons live here:
#
#   api-operation-id-removed            an operationId is what a generated client calls — the
#                                       interface's own included (`npm run generate:api`); a renamed
#                                       one breaks it at compile time (0043 §1, `PublishedOperationIdsTest`)
#   response-optional-property-removed  springdoc marks no response property required, so every
#                                       field the API returns is "optional" to oasdiff and its removal
#                                       an info; to a client reading it, it is a removed field
#   response-property-type-compatible,  springdoc declares most responses as `*/*`, which oasdiff
#   response-body-type-compatible,      takes for a weakly typed medium where `string` → `integer`
#   request-property-type-compatible,   is harmless. The API speaks JSON on every one of them, where
#   request-body-type-compatible        it is not
#   response-media-type-name-changed    a client asks for the media type it parses
#
# and one lowered, the other way:
#
#   response-property-enum-value-added  enum values are open (0043 §1): a client meeting a value it
#                                       does not know shows it as sent, as the interface does
#                                       (0019). Left an error, it was 136 of the 173 breaks between
#                                       v0.10.0 and 0.11 — one added value multiplied by every
#                                       operation returning the schema — and a list that loud is
#                                       one nobody reads
cat > "$WORK/severity-levels.txt" <<'LEVELS'
api-operation-id-removed ERR
response-optional-property-removed ERR
response-property-type-compatible ERR
response-body-type-compatible ERR
request-property-type-compatible ERR
request-body-type-compatible ERR
response-media-type-name-changed ERR
response-property-enum-value-added INFO
LEVELS
chmod 0644 "$WORK/severity-levels.txt"

# **A green check is only worth what it read** (`quality-gate`): the two documents are counted
# before the diff, and a run over a document with no operation refuses rather than passes.
python3 - "$WORK/base.json" "$WORK/head.json" "$BASE_TAG" <<'PY'
import json, sys
methods = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
for path, label in ((sys.argv[1], sys.argv[3]), (sys.argv[2], "HEAD")):
    with open(path) as f:
        doc = json.load(f)
    ops = sum(1 for item in doc.get("paths", {}).values() for m in item if m in methods)
    if ops == 0:
        sys.exit(f"FAILED: {label}'s openapi.json holds no operation — nothing would be compared")
    print(f"  {label:<14} {len(doc['paths'])} paths, {ops} operations")
PY

docker run --rm -v "$WORK:/s:ro" "$OASDIFF_IMAGE" breaking /s/base.json /s/head.json \
  --severity-levels /s/severity-levels.txt --format json > "$WORK/breaks.json" \
  || fail "oasdiff could not compare the two documents"
# The readable form, for the log; the verdict is taken from the JSON above.
docker run --rm -v "$WORK:/s:ro" "$OASDIFF_IMAGE" breaking /s/base.json /s/head.json \
  --severity-levels /s/severity-levels.txt --format text || true

python3 - "$WORK/breaks.json" "$ACCEPTED" "$BASE_TAG" <<'PY'
import json, sys

breaks_file, accepted_file, base = sys.argv[1:4]
with open(breaks_file) as f:
    text = f.read().strip()
breaks = json.loads(text) if text else []
if not isinstance(breaks, list):
    sys.exit(f"FAILED: oasdiff answered something that is not a list of changes: {text[:200]}")

ERR = 3
def key(b):
    return (b["id"], f'{b.get("operation", "")} {b.get("path", "")}'.strip(), b["text"])

accepted, problems = {}, []
with open(accepted_file) as f:
    for n, line in enumerate(f, 1):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) != 5 or not all(parts):
            problems.append(f"{accepted_file}:{n}: expected `tag | rule id | METHOD /path | text | reason`, five non-empty fields")
            continue
        tag, rule, where, said, reason = parts
        if tag != base:
            problems.append(f"{accepted_file}:{n}: accepted against {tag}, the base is now {base} — the break shipped in a release; remove the line")
            continue
        accepted[(rule, where, said)] = n

errors = [b for b in breaks if b.get("level", 0) >= ERR]
unaccepted = [b for b in errors if key(b) not in accepted]
used = {accepted[key(b)] for b in errors if key(b) in accepted}
for k, n in accepted.items():
    if n not in used:
        problems.append(f"{accepted_file}:{n}: accepts `{k[0]}` on {k[1]}, which no longer happens — remove the line")

print(f"\n  against {base}: {len(breaks)} change(s) reported, {len(errors)} breaking, "
      f"{len(errors) - len(unaccepted)} accepted in {accepted_file}")
for b in unaccepted:
    w = f'{b.get("operation", "")} {b.get("path", "")}'.strip()
    print(f"  BREAKING [{b['id']}] {w}: {b['text']}")
    print(f"    to accept it, after review: {base} | {b['id']} | {w} | {b['text']} | <why>")
for p in problems:
    print(f"  {p}")
if unaccepted or problems:
    sys.exit("FAILED: the API breaks its clients against the last release (decision 0043 §1)")
print("  no unaccepted break")
PY
