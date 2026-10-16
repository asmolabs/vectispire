#!/bin/sh
# The lints that would panic or wrap on hostile input, held to a ceiling that only goes down.
#
# Indexing, slicing and arithmetic are not denied (Cargo.toml says why): the parsers that use them check
# their bounds first, and rewriting them belongs to the streams that own them. A new one is still a new
# place where a scanner's output can end a scan, so the count per lint may not grow. It may shrink —
# lower the ceiling in the same commit, which is how it ratchets (the i18n checks work the same way).
#
# Shipped code only (`--lib --bins`): a test that indexes fails loudly, which is what a test is for.
set -eu
cd "$(dirname "$0")/.."

CEILINGS=security/lint-ceilings.txt
lints=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$CEILINGS" | awk '{print $1}')
[ -n "$lints" ] || { echo "$CEILINGS lists no lint: the check would count nothing"; exit 1; }

args=""
for lint in $lints; do args="$args -W clippy::$lint"; done
# shellcheck disable=SC2086 # one -W per lint, split on purpose
out=$(cargo clippy --workspace --lib --bins --locked --message-format=json -q -- $args 2>/dev/null)

bad=0
for lint in $lints; do
  ceiling=$(awk -v l="$lint" '$1 == l {print $2}' "$CEILINGS")
  found=$(printf '%s\n' "$out" | grep -o "\"code\":{\"code\":\"clippy::$lint\"" | wc -l | tr -d ' ')
  if [ "$found" -gt "$ceiling" ]; then
    echo "clippy::$lint: $found, above its ceiling of $ceiling — a new place where input can panic or wrap"
    bad=1
  elif [ "$found" -lt "$ceiling" ]; then
    echo "clippy::$lint: $found, below its ceiling of $ceiling — lower it in $CEILINGS"
    bad=1
  else
    echo "clippy::$lint: $found (ceiling $ceiling)"
  fi
done
exit "$bad"
