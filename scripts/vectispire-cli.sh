#!/usr/bin/env sh
# ==============================================================================
# Vectispire CLI & CI/CD Runner
# ==============================================================================
# Lightweight automation CLI for the Vectispire control plane: POSIX sh and curl, jq when it is
# there. Compatible with Alpine, Debian/Ubuntu, macOS, GitLab CI, GitHub Actions, Jenkins.
#
# Exit codes are the gate script's (`ci/vectispire-gate.sh`), and three rather than two on purpose:
#   0  done — the gate passed, the scan completed, the file was sent
#   1  the gate failed: findings above the policy. Nothing else exits 1
#   2  no answer to trust — a refusal (the server's `detail` is printed), the control plane
#      unreachable, a scan that failed or did not finish in time, a usage error
#
# **2 is not 1.** This used to be `curl -s -f` everywhere: every refusal exited with curl's own 22
# and printed nothing, so "the key lacks the read scope" and "your repository fails the policy"
# looked alike in a pipeline log, and neither said which.
# ==============================================================================

# The colour variables below are constants of this file, never input, so they go in printf's format
# string on purpose — that is what turns `\033` into an escape.
# shellcheck disable=SC2059
set -e

VERSION="1.1.0"

# Defaults from environment or arguments
VECTISPIRE_URL="${VECTISPIRE_URL:-http://localhost:3180}"
VECTISPIRE_API_KEY="${VECTISPIRE_API_KEY:-}"
VECTISPIRE_TOKEN="${VECTISPIRE_TOKEN:-}"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

print_header() {
    printf "${CYAN}${BOLD}Vectispire CLI${NC} v%s (ASPM & Security Gate Runner)\n" "$VERSION"
}

usage() {
    print_header
    cat << 'EOF'

Usage:
  vectispire-cli <command> [options]

Commands:
  scan          Trigger a security scan on a repository or container
  gate          Evaluate the security gate: exit 0 (passed), 1 (failed) or 2 (could not be asked)
  status        Show the status of a scan, or of the latest scan of a target
  sbom          Download a scan's SBOM, in Syft's native JSON, as the cataloguer produced it
  coverage      Send a coverage report (JaCoCo, Cobertura, lcov) for a repository
  test-report   Send a JUnit test report (one XML file, or a zip of them) for a repository
  version       Display CLI version

Global Options:
  --url <url>             Vectispire Control Plane URL (default: $VECTISPIRE_URL or http://localhost:3180)
  --api-key <key>         API Key for authentication (or set $VECTISPIRE_API_KEY)
  --token <token>         Bearer token (or set $VECTISPIRE_TOKEN)
  -h, --help              Show this help message

Scan Options (key scopes: scan, plus read for --wait):
  --repo-id <id>          Target repository ID
  --container-id <id>     Target container ID
  --wait                  Wait for scan completion before returning
  --timeout <sec>         Max seconds to wait (default: 300)
  A scan of the target already waiting (HTTP 409) is adopted rather than refused.

Gate Options (key scope: scan):
  --repo-id <id>          Target repository ID
  --container-id <id>     Target container ID
  --fail-on <severity>    Tighten the failure threshold (critical, high, medium, low)
  --fail-on-kev           Fail if any CISA KEV (Known Exploited Vulnerability) is detected
  --fixable-only          Only consider vulnerabilities with known fixes

Status Options (key scope: read):
  --scan-id <id>          A specific scan
  --repo-id <id>          The latest scan of this repository
  --container-id <id>     The latest scan of this container

SBOM Options (key scope: read):
  --scan-id <id>          Specific scan ID
  --repo-id <id>          The latest *completed* scan of this repository
  --output <file>         Output filepath (default: stdout)
  For a CycloneDX document, with the issues as VEX, use the export instead (key scope: export):
  GET /api/v1/cyclonedx/scans/<scan-id>/cyclonedx-vex.json

Report Options (coverage, test-report):
  --repo-id <id>          Target repository ID (required)
  --file <path>           The report to send (required)
  --format <format>       coverage only: jacoco, cobertura or lcov (required, never guessed)
  --commit <sha>          The commit the report was produced from (kept as stated)
  --branch <name>         The branch it was produced on (kept as stated)
  The key must hold the report_import scope and be declared as a source delivering
  coverage or test_report, or the report is refused.

Exit codes:
  0  done: gate passed, scan completed, file sent
  1  the gate failed — findings above the policy
  2  no answer to trust: a refusal (its detail is printed), the control plane unreachable,
     a scan that failed or timed out, a usage error

Examples:
  # Trigger scan and wait in CI/CD pipeline
  vectispire-cli scan --repo-id 1 --wait

  # Enforce CI/CD Quality Gate (fails build if gate fails)
  vectispire-cli gate --repo-id 1 --fail-on high

  # Download the SBOM of the latest completed scan
  vectispire-cli sbom --repo-id 1 --output ./artifacts/sbom.syft.json

  # Send the pipeline's coverage and test results
  vectispire-cli coverage --repo-id 1 --format jacoco --file target/site/jacoco/jacoco.xml --commit "$CI_COMMIT_SHA"
  vectispire-cli test-report --repo-id 1 --file target/surefire-reports.zip

EOF
    exit "${1:-0}"
}

# Everything that is not a verdict ends here: 2, "no answer to trust".
die() {
    printf "${RED}✘ %s${NC}\n" "$1" >&2
    exit 2
}

get_auth_header() {
    if [ -n "$VECTISPIRE_API_KEY" ]; then
        printf "X-API-Key: %s" "$VECTISPIRE_API_KEY"
    elif [ -n "$VECTISPIRE_TOKEN" ]; then
        printf "Authorization: Bearer %s" "$VECTISPIRE_TOKEN"
    else
        printf ""
    fi
}

require_auth() {
    AUTH_HEADER=$(get_auth_header)
    if [ -z "$AUTH_HEADER" ]; then
        die "Authentication required. Provide --api-key <key> or set VECTISPIRE_API_KEY."
    fi
}

# The human sentence of a problem document (RFC 9457): `detail`, else `title`. Every refusal the
# control plane writes is one, and its `detail` is written for the person reading the log — "This
# API key lacks the read scope." is the answer, the status alone is a riddle.
problem_detail() {
    if command -v jq >/dev/null 2>&1; then
        printf "%s" "$1" | jq -r '.detail // .title // empty' 2>/dev/null || true
    else
        printf "%s" "$1" | sed -n 's/.*"detail" *: *"\([^"]*\)".*/\1/p' | head -n1
    fi
}

# One request; sets HTTP_STATUS and HTTP_BODY and never exits, so that a caller can decide that a
# 409 is not a failure. Not meant for `$(…)`: the two variables would stay in the subshell.
#   api METHOD ENDPOINT [JSON_BODY | @FILE CONTENT_TYPE] [OUTPUT_FILE]
api() {
    METHOD="$1"
    ENDPOINT="$2"
    DATA="${3:-}"
    CONTENT_TYPE="${4:-application/json}"
    OUT_FILE="${5:-}"
    RESPONSE_FILE=$(mktemp)
    set -- -sS --location --max-time "${VECTISPIRE_HTTP_TIMEOUT:-60}" \
        -o "$RESPONSE_FILE" -w "%{http_code}" -H "$AUTH_HEADER" -H "Accept: application/json" -X "$METHOD"
    case "$DATA" in
        "") ;;
        @*) set -- "$@" -H "Content-Type: $CONTENT_TYPE" --data-binary "$DATA" ;;
        *) set -- "$@" -H "Content-Type: application/json" --data "$DATA" ;;
    esac
    HTTP_STATUS=$(curl "$@" "${VECTISPIRE_URL%/}${ENDPOINT}") || HTTP_STATUS="000"
    case "$HTTP_STATUS" in
        2*)
            if [ -n "$OUT_FILE" ]; then
                mv "$RESPONSE_FILE" "$OUT_FILE"
                HTTP_BODY=""
                return 0
            fi ;;
    esac
    HTTP_BODY=$(cat "$RESPONSE_FILE")
    rm -f "$RESPONSE_FILE"
}

# Stops on anything but a 2xx, with the server's own words.
refused() {
    if [ "$HTTP_STATUS" = "000" ]; then
        die "Could not reach $VECTISPIRE_URL ($METHOD $ENDPOINT): the control plane did not answer."
    fi
    DETAIL=$(problem_detail "$HTTP_BODY")
    if [ -z "$DETAIL" ]; then
        # Not a problem document — a proxy's page, say. Shown as it came, cut short.
        DETAIL=$(printf "%s" "$HTTP_BODY" | head -c 500)
    fi
    die "Refused: $METHOD $ENDPOINT answered HTTP $HTTP_STATUS${DETAIL:+ — $DETAIL}"
}

api_ok() {
    api "$@"
    case "$HTTP_STATUS" in
        2*) ;;
        *) refused ;;
    esac
}

# The first scan of a history (newest first) in a given status, or nothing. The history's entries
# are flat objects, which is what the jq-less fallback relies on.
first_scan_with_status() {
    if command -v jq >/dev/null 2>&1; then
        printf "%s" "$2" | jq -r --arg s "$1" '[.[] | select(.status == $s)][0].id // empty'
    else
        printf "%s" "$2" | tr '{' '\n' | grep -E "\"status\" *: *\"$1\"" | head -n1 | json_scalar id
    fi
}

first_scan() {
    if command -v jq >/dev/null 2>&1; then
        printf "%s" "$1" | jq -r '.[0].id // empty'
    else
        printf "%s" "$1" | json_scalar id
    fi
}

# The first `"key": value` in a document read on stdin — a number, a boolean, null or a string
# without quotes in it — whitespace or not around the colon. Enough for the flat fields this
# reads; the first occurrence is the outermost one in every answer it is used on.
json_scalar() {
    grep -oE "\"$1\" *: *(\"[^\"]*\"|[0-9A-Za-z.]+)" | head -n1 | sed -e 's/^[^:]*: *//' -e 's/^"//' -e 's/"$//'
}

json_status() {
    printf "%s" "$1" | json_scalar status
}

# `?repo_id=` or `?container_id=`, for the history route.
history_filter() {
    if [ -n "$REPO_ID" ]; then printf "repo_id=%s" "$REPO_ID"; else printf "container_id=%s" "$CONTAINER_ID"; fi
}

cmd_scan() {
    REPO_ID=""
    CONTAINER_ID=""
    WAIT=0
    TIMEOUT=300

    while [ $# -gt 0 ]; do
        case "$1" in
            --repo-id) REPO_ID="$2"; shift 2 ;;
            --container-id) CONTAINER_ID="$2"; shift 2 ;;
            --wait) WAIT=1; shift ;;
            --timeout) TIMEOUT="$2"; shift 2 ;;
            *) die "Unknown scan option: $1" ;;
        esac
    done

    require_auth

    if [ -z "$REPO_ID" ] && [ -z "$CONTAINER_ID" ]; then
        die "Specify either --repo-id <id> or --container-id <id>."
    fi

    printf "${BLUE}==> Enqueuing security scan on Vectispire...${NC}\n"
    if [ -n "$REPO_ID" ]; then
        api POST "/api/v1/repositories/${REPO_ID}/scan" "{}"
    else
        api POST "/api/v1/containers/${CONTAINER_ID}/scan" "{}"
    fi

    case "$HTTP_STATUS" in
        2*)
            SCAN_ID=$(printf "%s" "$HTTP_BODY" | json_scalar id)
            printf "${GREEN}✔ Scan queued${NC} (Scan ID: ${BOLD}%s${NC}, Status: %s)\n" "$SCAN_ID" "$(json_status "$HTTP_BODY")" ;;
        409)
            # A scan of this target is already waiting, and it will examine the same tree: wait
            # for that one. Failing here would fail every pipeline that runs while the schedule's
            # scan is queued.
            api_ok GET "/api/v1/scans?$(history_filter)&limit=20"
            SCAN_ID=$(first_scan_with_status pending "$HTTP_BODY")
            [ -n "$SCAN_ID" ] || die "HTTP 409 said a scan was waiting, and none is pending in the history."
            printf "${GREEN}✔ A scan was already queued${NC} (Scan ID: ${BOLD}%s${NC}): following it.\n" "$SCAN_ID" ;;
        *) refused ;;
    esac

    [ -n "$SCAN_ID" ] || die "The answer named no scan: $HTTP_BODY"

    if [ "$WAIT" -eq 1 ]; then
        printf "${BLUE}==> Waiting for scan completion (timeout: %ds)...${NC}\n" "$TIMEOUT"
        ELAPSED=0
        while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
            sleep "${VECTISPIRE_POLL_SECONDS:-3}"
            ELAPSED=$((ELAPSED + ${VECTISPIRE_POLL_SECONDS:-3}))

            api_ok GET "/api/v1/scans/${SCAN_ID}"
            STATUS=$(json_status "$HTTP_BODY")

            case "$STATUS" in
                completed)
                    printf "${GREEN}✔ Scan %s completed${NC}\n" "$SCAN_ID"
                    return 0
                    ;;
                failed)
                    # 2, not 1: a failed scan says nothing about the code, and a verdict asked
                    # now would describe the scan before it.
                    die "Scan $SCAN_ID failed: $(printf "%s" "$HTTP_BODY" | json_scalar error)"
                    ;;
                "")
                    die "The scan's detail carried no status: $(printf "%s" "$HTTP_BODY" | head -c 500)"
                    ;;
                *)
                    printf "    ... Scan in progress (status: %s, %ds elapsed)\n" "$STATUS" "$ELAPSED"
                    ;;
            esac
        done

        die "Scan $SCAN_ID is still running after ${TIMEOUT}s."
    fi
}

cmd_gate() {
    REPO_ID=""
    CONTAINER_ID=""
    FAIL_ON=""
    FAIL_ON_KEV=""
    FIXABLE_ONLY=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --repo-id) REPO_ID="$2"; shift 2 ;;
            --container-id) CONTAINER_ID="$2"; shift 2 ;;
            # The server spells severities in lower case; `HIGH` was the help's own example.
            --fail-on) FAIL_ON=$(printf "%s" "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
            --fail-on-kev) FAIL_ON_KEV="true"; shift ;;
            --fixable-only) FIXABLE_ONLY="true"; shift ;;
            *) die "Unknown gate option: $1" ;;
        esac
    done

    require_auth

    if [ -z "$REPO_ID" ] && [ -z "$CONTAINER_ID" ]; then
        die "Specify either --repo-id <id> or --container-id <id>."
    fi

    # Construct JSON payload
    BODY="{"
    if [ -n "$REPO_ID" ]; then
        BODY="${BODY}\"repository_id\":${REPO_ID}"
    else
        BODY="${BODY}\"container_id\":${CONTAINER_ID}"
    fi
    if [ -n "$FAIL_ON" ]; then
        BODY="${BODY},\"fail_on_severity\":\"${FAIL_ON}\""
    fi
    if [ -n "$FAIL_ON_KEV" ]; then
        BODY="${BODY},\"fail_on_kev\":true"
    fi
    if [ -n "$FIXABLE_ONLY" ]; then
        BODY="${BODY},\"fixable_only\":true"
    fi
    BODY="${BODY}}"

    printf "${BLUE}==> Evaluating Vectispire Security Quality Gate...${NC}\n"
    api_ok POST "/api/v1/gate" "$BODY"

    PASSED=$(printf "%s" "$HTTP_BODY" | json_scalar passed)
    EVALUATED=$(printf "%s" "$HTTP_BODY" | json_scalar evaluated)

    # A 200 that carries no verdict is not a pass: nothing decided, so 2.
    case "$PASSED" in
        true|false) ;;
        *) die "The gate answered HTTP $HTTP_STATUS without a verdict: $(printf "%s" "$HTTP_BODY" | head -c 500)" ;;
    esac

    RULE="------------------------------------------------------------"
    printf "\n%s\n Quality Gate Evaluation Summary\n%s\n" "$RULE" "$RULE"
    printf " Issues considered: %s\n" "$EVALUATED"
    if command -v jq >/dev/null 2>&1; then
        printf "%s" "$HTTP_BODY" | jq -r '" Policy: \(.policy.source) (version \(.policy.version // "—")), threshold \(.policy.failOnSeverity // "none")"'
        IGNORED=$(printf "%s" "$HTTP_BODY" | jq -r '(.ignored_relaxations // []) | join(", ")')
        [ -z "$IGNORED" ] || printf " Relaxation(s) refused and ignored: %s\n" "$IGNORED" >&2
    fi

    if [ "$PASSED" = "true" ]; then
        printf "\n${GREEN}${BOLD}✔ GATE PASSED:${NC} Security posture complies with the applied policy.\n\n"
        exit 0
    fi

    printf "\n${RED}${BOLD}✖ GATE FAILED:${NC} findings above the applied policy.\n" >&2
    if command -v jq >/dev/null 2>&1; then
        printf "%s" "$HTTP_BODY" | jq -r '.violations[]? | "  [\(.severity // "unknown")] \(.identifier // "issue #\(.issueId)") \(.package // "") — \(.reason)\(if .fixVersions then " (fixed in \(.fixVersions))" else "" end)"' >&2
    else
        printf " Install jq for the list of violations, or see the Verdict register.\n" >&2
    fi
    printf "\n" >&2
    exit 1
}

cmd_status() {
    SCAN_ID=""
    REPO_ID=""
    CONTAINER_ID=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --scan-id) SCAN_ID="$2"; shift 2 ;;
            --repo-id) REPO_ID="$2"; shift 2 ;;
            --container-id) CONTAINER_ID="$2"; shift 2 ;;
            *) die "Unknown status option: $1" ;;
        esac
    done

    require_auth

    if [ -z "$SCAN_ID" ]; then
        if [ -z "$REPO_ID" ] && [ -z "$CONTAINER_ID" ]; then
            die "Provide --scan-id <id>, --repo-id <id> or --container-id <id>."
        fi
        api_ok GET "/api/v1/scans?$(history_filter)&limit=1"
        SCAN_ID=$(first_scan "$HTTP_BODY")
        [ -n "$SCAN_ID" ] || die "This target has never been scanned."
    fi

    api_ok GET "/api/v1/scans/${SCAN_ID}"
    printf "Scan %s: %s\n" "$SCAN_ID" "$(json_status "$HTTP_BODY")"
}

cmd_sbom() {
    SCAN_ID=""
    REPO_ID=""
    OUTPUT=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --scan-id) SCAN_ID="$2"; shift 2 ;;
            --repo-id) REPO_ID="$2"; shift 2 ;;
            --output) OUTPUT="$2"; shift 2 ;;
            *) die "Unknown sbom option: $1" ;;
        esac
    done

    require_auth

    if [ -z "$SCAN_ID" ] && [ -n "$REPO_ID" ]; then
        # The latest *completed* scan. The newest one may be pending or running, which has no
        # SBOM yet (404), or failed before the inventory, which never will.
        api_ok GET "/api/v1/scans?repo_id=${REPO_ID}&limit=50"
        SCAN_ID=$(first_scan_with_status completed "$HTTP_BODY")
        [ -n "$SCAN_ID" ] || die "Repository ${REPO_ID} has no completed scan among its latest 50."
    fi

    if [ -z "$SCAN_ID" ]; then
        die "Provide --scan-id <id> or --repo-id <id>."
    fi

    printf "${BLUE}==> Downloading the SBOM of scan %s (Syft native JSON)...${NC}\n" "$SCAN_ID" >&2
    if [ -n "$OUTPUT" ]; then
        api_ok GET "/api/v1/scans/${SCAN_ID}/sbom" "" "" "$OUTPUT"
        printf "${GREEN}✔ SBOM saved to %s${NC}\n" "$OUTPUT" >&2
    else
        api_ok GET "/api/v1/scans/${SCAN_ID}/sbom"
        printf "%s\n" "$HTTP_BODY"
    fi
}

# The commit and branch go in the query string: percent-encode what a branch name may carry.
url_encode() {
    printf "%s" "$1" | od -An -tx1 -v | tr -d ' \n' | sed 's/\(..\)/%\1/g'
}

report_query() {
    QUERY=""
    [ -n "$FORMAT" ] && QUERY="${QUERY}&format=$(url_encode "$FORMAT")"
    [ -n "$COMMIT" ] && QUERY="${QUERY}&commit=$(url_encode "$COMMIT")"
    [ -n "$BRANCH" ] && QUERY="${QUERY}&branch=$(url_encode "$BRANCH")"
    [ -n "$QUERY" ] && printf "?%s" "${QUERY#&}"
    return 0
}

parse_report_options() {
    REPO_ID=""
    FILE=""
    FORMAT=""
    COMMIT=""
    BRANCH=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --repo-id) REPO_ID="$2"; shift 2 ;;
            --file) FILE="$2"; shift 2 ;;
            --format) FORMAT="$2"; shift 2 ;;
            --commit) COMMIT="$2"; shift 2 ;;
            --branch) BRANCH="$2"; shift 2 ;;
            *) die "Unknown report option: $1" ;;
        esac
    done
    require_auth
    if [ -z "$REPO_ID" ] || [ -z "$FILE" ]; then
        die "Provide --repo-id <id> and --file <path>."
    fi
    if [ ! -f "$FILE" ]; then
        die "No such file: $FILE"
    fi
}

# Sends a file as the request body and prints the server's answer, which counts what it recorded.
upload_report() {
    api_ok POST "$1" "@$3" "$2"
    printf "%s\n" "$HTTP_BODY"
}

cmd_coverage() {
    parse_report_options "$@"
    if [ -z "$FORMAT" ]; then
        # The server refuses an undeclared format rather than guessing; saying so here saves a round trip.
        die "Provide --format jacoco, cobertura or lcov."
    fi
    case "$FORMAT" in
        lcov) CONTENT_TYPE="text/plain" ;;
        *) CONTENT_TYPE="application/xml" ;;
    esac
    printf "${BLUE}==> Sending %s coverage for repository %s...${NC}\n" "$FORMAT" "$REPO_ID" >&2
    upload_report "/api/v1/repositories/${REPO_ID}/coverage-imports$(report_query)" "$CONTENT_TYPE" "$FILE"
    printf "${GREEN}✔ Coverage recorded${NC}\n" >&2
}

cmd_test_report() {
    parse_report_options "$@"
    if [ -n "$FORMAT" ]; then
        die "--format is for coverage; a test report is JUnit, a zip when the file ends in .zip."
    fi
    case "$FILE" in
        *.zip) CONTENT_TYPE="application/zip" ;;
        *) CONTENT_TYPE="application/xml" ;;
    esac
    printf "${BLUE}==> Sending the test report for repository %s...${NC}\n" "$REPO_ID" >&2
    upload_report "/api/v1/repositories/${REPO_ID}/test-report-imports$(report_query)" "$CONTENT_TYPE" "$FILE"
    printf "${GREEN}✔ Test report recorded${NC}\n" >&2
}

# --- CLI Entrypoint ---

COMMAND="${1:-}"
if [ -z "$COMMAND" ] || [ "$COMMAND" = "-h" ] || [ "$COMMAND" = "--help" ]; then
    usage
fi
shift

# Parse global options first if present
while [ $# -gt 0 ]; do
    case "$1" in
        --url) VECTISPIRE_URL="$2"; shift 2 ;;
        --api-key) VECTISPIRE_API_KEY="$2"; shift 2 ;;
        --token) VECTISPIRE_TOKEN="$2"; shift 2 ;;
        *) break ;;
    esac
done

case "$COMMAND" in
    scan) cmd_scan "$@" ;;
    gate) cmd_gate "$@" ;;
    status) cmd_status "$@" ;;
    sbom) cmd_sbom "$@" ;;
    coverage) cmd_coverage "$@" ;;
    test-report) cmd_test_report "$@" ;;
    version|--version|-v) printf "vectispire-cli v%s\n" "$VERSION" ;;
    *)
        printf "${RED}Unknown command: %s${NC}\n" "$COMMAND" >&2
        usage 2 >&2
        ;;
esac
