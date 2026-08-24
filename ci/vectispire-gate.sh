#!/usr/bin/env sh
#
# Ask Vectispire whether this build should fail.
#
# The control plane has answered this question since the first release — POST /api/v1/gate
# returns a verdict, the violations behind it, and the policy it applied — and nothing called
# it. A dashboard tells somebody who goes and looks; a gate tells the build. This is the twenty
# lines that were missing between the two.
#
# Usage:
#   VECTISPIRE_URL=https://vectispire.example.com \
#   VECTISPIRE_TOKEN=zsk_… \
#   ./vectispire-gate.sh --repository 12
#
#   ./vectispire-gate.sh --container 4 --fail-on-severity critical
#
# Exit codes, and they are three rather than two on purpose:
#   0  the gate passed
#   1  the gate failed — findings above the policy
#   2  the gate could not be asked — network, credential, unknown target
#
# **2 is not 1.** A pipeline that treats "Vectispire was unreachable" as "your code is clean" has
# no gate at all on the day the control plane is down; one that treats it as a failed build
# blocks every team for a reason none of them can fix. Which of the two you want is a decision,
# so it is `--on-error`, and its default is to block: a gate that fails open is a gate that
# stops protecting you exactly when nobody is watching.

set -eu

fail_on_severity=""
fail_on_kev=""
fixable_only=""
include_triaged=""
target_kind=""
target_id=""
on_error="fail"
quiet=""

usage() {
    sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repository) target_kind="repository_id"; target_id="$2"; shift 2 ;;
        --container) target_kind="container_id"; target_id="$2"; shift 2 ;;
        --fail-on-severity) fail_on_severity="$2"; shift 2 ;;
        --fail-on-kev) fail_on_kev="$2"; shift 2 ;;
        --fixable-only) fixable_only="$2"; shift 2 ;;
        --include-triaged) include_triaged="$2"; shift 2 ;;
        --on-error) on_error="$2"; shift 2 ;;
        --quiet) quiet="yes"; shift ;;
        -h|--help) usage ;;
        *) echo "vectispire-gate: unknown argument \"$1\"" >&2; usage ;;
    esac
done

VECTISPIRE_URL="${VECTISPIRE_URL:-${VERISCAPE_URL:-${ZANSHIN_URL:-}}}"
VECTISPIRE_TOKEN="${VECTISPIRE_TOKEN:-${VERISCAPE_TOKEN:-${ZANSHIN_TOKEN:-}}}"

: "${VECTISPIRE_URL:?set VECTISPIRE_URL to the control plane, e.g. https://vectispire.example.com}"
: "${VECTISPIRE_TOKEN:?set VECTISPIRE_TOKEN to an API key (Administration → API keys)}"

if [ -z "$target_kind" ]; then
    echo "vectispire-gate: give --repository <id> or --container <id>." >&2
    exit 2
fi

body="{\"$target_kind\": $target_id"
if [ -n "$fail_on_severity" ]; then body="$body, \"fail_on_severity\": \"$fail_on_severity\""; fi
if [ -n "$fail_on_kev" ]; then body="$body, \"fail_on_kev\": $fail_on_kev"; fi
if [ -n "$fixable_only" ]; then body="$body, \"fixable_only\": $fixable_only"; fi
if [ -n "$include_triaged" ]; then body="$body, \"include_triaged\": $include_triaged"; fi
body="$body}"

response_file=$(mktemp)
trap 'rm -f "$response_file"' EXIT

status=$(curl --silent --show-error --location \
    --max-time "${VECTISPIRE_TIMEOUT:-${VERISCAPE_TIMEOUT:-${ZANSHIN_TIMEOUT:-30}}}" \
    --write-out '%{http_code}' \
    --output "$response_file" \
    --header "Authorization: Bearer $VECTISPIRE_TOKEN" \
    --header 'Content-Type: application/json' \
    --data "$body" \
    "${VECTISPIRE_URL%/}/api/v1/gate") || status="000"

if [ "$status" != "200" ]; then
    echo "vectispire-gate: the gate could not be asked (HTTP $status)." >&2
    if [ -s "$response_file" ]; then sed -e 's/^/  /' "$response_file" >&2; fi
    if [ "$status" = "000" ]; then echo "  The control plane did not answer at all: $VECTISPIRE_URL" >&2; fi
    if [ "$on_error" = "warn" ]; then
        echo "vectispire-gate: --on-error=warn, so the build continues **ungated**." >&2
        exit 0
    fi
    exit 2
fi

if command -v jq >/dev/null 2>&1; then
    passed=$(jq -r '.passed' "$response_file")
    evaluated=$(jq -r '.evaluated' "$response_file")
    source=$(jq -r '.policy.source' "$response_file")
    version=$(jq -r '.policy.version // "—"' "$response_file")
    threshold=$(jq -r '.policy.failOnSeverity // "none"' "$response_file")
    ignored=$(jq -r '.ignored_relaxations | join(", ")' "$response_file")

    if [ -z "$quiet" ]; then
        printf 'Vectispire gate: %s policy (version %s), threshold %s, %s issue(s) considered.\n' \
            "$source" "$version" "$threshold" "$evaluated"
    fi

    if [ -n "$ignored" ]; then echo "Vectispire gate: relaxation(s) refused and ignored: $ignored" >&2; fi

    if [ "$passed" = "true" ]; then
        if [ -z "$quiet" ]; then echo "Vectispire gate: passed."; fi
        exit 0
    fi

    echo "Vectispire gate: FAILED." >&2
    jq -r '.violations[] | "  [\(.severity // "unknown")] \(.identifier // "issue #\(.issueId)") \(.package // "") — \(.reason)\(if .fixVersions then " (fixed in \(.fixVersions))" else "" end)"' \
        "$response_file" >&2
    exit 1
fi

if grep -q '"passed":true' "$response_file"; then
    if [ -z "$quiet" ]; then echo "Vectispire gate: passed. (Install jq for the detail.)"; fi
    exit 0
fi
echo "Vectispire gate: FAILED. (Install jq for the detail.)" >&2
cat "$response_file" >&2
exit 1
