#!/bin/sh
# The lints that would panic or wrap on hostile input, held to a ceiling that only goes down.
#
# Indexing, slicing and arithmetic are not denied (Cargo.toml says why): the parsers that use them check
# their bounds first, and rewriting them belongs to the streams that own them. A new one is still a new
# place where a scanner's output can end a scan, so the count per lint may not grow. It may shrink —
# lower the ceiling in the same commit, which is how it ratchets (the i18n checks work the same way).
#
# Two scopes, each with its own ceiling: the agent's crates, and the control plane's (`crates/cp-*` and
# `crates/migrate`). One ceiling for both would let the agent's count grow into the slack the control plane's
# newer crates leave, and the other way round.
#
# Shipped code only (`--lib --bins`): a test that indexes fails loudly, which is what a test is for.
set -eu
cd "$(dirname "$0")/.."

CEILINGS=security/lint-ceilings.txt
lints=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$CEILINGS" | awk '{print $1}')
[ -n "$lints" ] || { echo "$CEILINGS lists no lint: the check would count nothing"; exit 1; }

args=""
for lint in $lints; do args="$args -W clippy::$lint"; done
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
# shellcheck disable=SC2086 # one -W per lint, split on purpose
cargo clippy --workspace --lib --bins --locked --message-format=json -q -- $args 2>/dev/null > "$tmp"

# One "<lint> <scope> <count>" line per lint and scope, zero included, so a lint that vanished is seen.
# shellcheck disable=SC2086 # one argument per lint, split on purpose
counts=$(python3 - "$tmp" $lints <<'PY'
import collections, json, sys

counts = collections.Counter()
for line in open(sys.argv[1]):
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if message.get("reason") != "compiler-message":
        continue
    body = message["message"]
    code = (body.get("code") or {}).get("code", "")
    if not code.startswith("clippy::"):
        continue
    primary = [span for span in body["spans"] if span.get("is_primary")]
    file = primary[0]["file_name"] if primary else ""
    crate = file.split("/")[1] if file.startswith("crates/") else ""
    scope = "control-plane" if crate.startswith("cp-") or crate == "migrate" else "agent"
    counts[(code[len("clippy::"):], scope)] += 1
for lint in sys.argv[2:]:
    for scope in ("agent", "control-plane"):
        print(lint, scope, counts[(lint, scope)])
PY
)

bad=0
echo "$counts" | while read -r lint scope found; do
  col=2; [ "$scope" = "control-plane" ] && col=3
  ceiling=$(awk -v l="$lint" -v c="$col" '$1 == l {print $c}' "$CEILINGS")
  if [ "$found" -gt "$ceiling" ]; then
    echo "clippy::$lint ($scope): $found, above its ceiling of $ceiling — a new place where input can panic or wrap"
    echo bad >> "$tmp.bad"
  elif [ "$found" -lt "$ceiling" ]; then
    echo "clippy::$lint ($scope): $found, below its ceiling of $ceiling — lower it in $CEILINGS"
    echo bad >> "$tmp.bad"
  else
    echo "clippy::$lint ($scope): $found (ceiling $ceiling)"
  fi
done
# the loop above runs in a subshell: its verdict comes back through a file
if [ -e "$tmp.bad" ]; then rm -f "$tmp.bad"; bad=1; fi
exit "$bad"
