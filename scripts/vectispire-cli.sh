#!/usr/bin/env sh
# ==============================================================================
# Vectispire CLI & CI/CD Runner
# ==============================================================================
# Lightweight, dependency-free automation CLI for Vectispire Control Plane.
# Compatible with POSIX sh, Alpine, Debian/Ubuntu, macOS, GitLab CI, GitHub Actions.
# ==============================================================================

set -e

VERSION="1.0.0"

# Defaults from environment or arguments
VECTISPIRE_URL="${VECTISPIRE_URL:-http://localhost:3180}"
VECTISPIRE_API_KEY="${VECTISPIRE_API_KEY:-}"
VECTISPIRE_TOKEN="${VECTISPIRE_TOKEN:-}"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
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
  gate          Evaluate the security gate and return exit code 0 (PASS) or 1 (FAIL)
  sbom          Download the SBOM (CycloneDX / SPDX JSON) for a scan or repository
  status        Check the status of the latest scan on a target
  version       Display CLI version

Global Options:
  --url <url>             Vectispire Control Plane URL (default: $VECTISPIRE_URL or http://localhost:3180)
  --api-key <key>         API Key for authentication (or set $VECTISPIRE_API_KEY)
  --token <token>         Bearer JWT token (or set $VECTISPIRE_TOKEN)
  -h, --help              Show this help message

Scan Options:
  --repo-id <id>          Target repository ID
  --container-id <id>     Target container ID
  --wait                  Wait for scan completion before returning
  --timeout <sec>         Max seconds to wait (default: 300)

Gate Options:
  --repo-id <id>          Target repository ID
  --container-id <id>     Target container ID
  --fail-on <severity>    Override minimum failure severity (CRITICAL, HIGH, MEDIUM, LOW)
  --fail-on-kev           Fail if any CISA KEV (Known Exploited Vulnerability) is detected
  --fixable-only          Only consider vulnerabilities with known fixes

SBOM Options:
  --scan-id <id>          Specific scan ID
  --repo-id <id>          Fetch latest scan SBOM for this repository ID
  --output <file>         Output filepath (default: stdout or vectispire-sbom.json)

Examples:
  # Trigger scan and wait in CI/CD pipeline
  vectispire-cli scan --repo-id 1 --wait

  # Enforce CI/CD Quality Gate (fails build if gate fails)
  vectispire-cli gate --repo-id 1 --fail-on HIGH

  # Download latest scan SBOM
  vectispire-cli sbom --repo-id 1 --output ./artifacts/sbom.json

EOF
    exit 0
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
        printf "${RED}Error: Authentication required.${NC} Please provide --api-key <key> or set VECTISPIRE_API_KEY.\n" >&2
        exit 1
    fi
}

http_get() {
    ENDPOINT="$1"
    AUTH_HEADER=$(get_auth_header)
    if [ -n "$AUTH_HEADER" ]; then
        curl -s -f -H "$AUTH_HEADER" -H "Accept: application/json" "${VECTISPIRE_URL}${ENDPOINT}"
    else
        curl -s -f -H "Accept: application/json" "${VECTISPIRE_URL}${ENDPOINT}"
    fi
}

http_post() {
    ENDPOINT="$1"
    DATA="$2"
    AUTH_HEADER=$(get_auth_header)
    if [ -n "$AUTH_HEADER" ]; then
        curl -s -f -H "$AUTH_HEADER" -H "Content-Type: application/json" -H "Accept: application/json" -X POST -d "$DATA" "${VECTISPIRE_URL}${ENDPOINT}"
    else
        curl -s -f -H "Content-Type: application/json" -H "Accept: application/json" -X POST -d "$DATA" "${VECTISPIRE_URL}${ENDPOINT}"
    fi
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
            *) printf "${RED}Unknown scan option: %s${NC}\n" "$1" >&2; exit 1 ;;
        esac
    done

    require_auth

    if [ -z "$REPO_ID" ] && [ -z "$CONTAINER_ID" ]; then
        printf "${RED}Error: Specify either --repo-id <id> or --container-id <id>.${NC}\n" >&2
        exit 1
    fi

    printf "${BLUE}==> Enqueuing security scan on Vectispire...${NC}\n"
    if [ -n "$REPO_ID" ]; then
        RESPONSE=$(http_post "/api/v1/repositories/${REPO_ID}/scan" "{}")
    else
        RESPONSE=$(http_post "/api/v1/containers/${CONTAINER_ID}/scan" "{}")
    fi

    SCAN_ID=$(printf "%s" "$RESPONSE" | grep -o '"id":[0-9]*' | head -n1 | cut -d':' -f2)
    SCAN_STATUS=$(printf "%s" "$RESPONSE" | grep -o '"status":"[^"]*"' | head -n1 | cut -d'"' -f4)

    printf "${GREEN}✔ Scan queued successfully!${NC} (Scan ID: ${BOLD}%s${NC}, Status: %s)\n" "$SCAN_ID" "$SCAN_STATUS"

    if [ "$WAIT" -eq 1 ]; then
        printf "${BLUE}==> Waiting for scan completion (timeout: %ds)...${NC}\n" "$TIMEOUT"
        ELAPSED=0
        while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
            sleep 3
            ELAPSED=$((ELAPSED + 3))

            SCAN_DETAIL=$(http_get "/api/v1/scans/${SCAN_ID}")
            STATUS=$(printf "%s" "$SCAN_DETAIL" | grep -o '"status":"[^"]*"' | head -n1 | cut -d'"' -f4)

            case "$STATUS" in
                "completed"|"passed"|"done")
                    printf "${GREEN}✔ Scan %s finished successfully!${NC}\n" "$SCAN_ID"
                    return 0
                    ;;
                "failed"|"error")
                    printf "${RED}✖ Scan %s failed!${NC}\n" "$SCAN_ID" >&2
                    exit 1
                    ;;
                *)
                    printf "    ... Scan in progress (status: %s, %ds elapsed)\n" "$STATUS" "$ELAPSED"
                    ;;
            esac
        done

        printf "${RED}✖ Timeout reached while waiting for scan %s.${NC}\n" "$SCAN_ID" >&2
        exit 1
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
            --fail-on) FAIL_ON="$2"; shift 2 ;;
            --fail-on-kev) FAIL_ON_KEV="true"; shift ;;
            --fixable-only) FIXABLE_ONLY="true"; shift ;;
            *) printf "${RED}Unknown gate option: %s${NC}\n" "$1" >&2; exit 1 ;;
        esac
    done

    require_auth

    if [ -z "$REPO_ID" ] && [ -z "$CONTAINER_ID" ]; then
        printf "${RED}Error: Specify either --repo-id <id> or --container-id <id>.${NC}\n" >&2
        exit 1
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
    RESPONSE=$(http_post "/api/v1/gate" "$BODY")

    PASSED=$(printf "%s" "$RESPONSE" | grep -o '"passed":\(true\|false\)' | cut -d':' -f2)
    EVALUATED=$(printf "%s" "$RESPONSE" | grep -o '"evaluated":[0-9]*' | cut -d':' -f2)

    printf "\n------------------------------------------------------------\n"
    printf " Quality Gate Evaluation Summary\n"
    printf "------------------------------------------------------------\n"
    printf " Total Findings Evaluated: %s\n" "$EVALUATED"

    if [ "$PASSED" = "true" ]; then
        printf "\n${GREEN}${BOLD}✔ GATE PASSED:${NC} Security posture complies with defined policy rules.\n\n"
        exit 0
    else
        printf "\n${RED}${BOLD}✖ GATE FAILED:${NC} Critical security policy violations detected.\n"
        printf " Check Vectispire console for remediation guidance.\n\n"
        exit 1
    fi
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
            *) printf "${RED}Unknown sbom option: %s${NC}\n" "$1" >&2; exit 1 ;;
        esac
    done

    require_auth

    if [ -z "$SCAN_ID" ] && [ -n "$REPO_ID" ]; then
        # Find latest scan for this repo
        SCANS_JSON=$(http_get "/api/v1/scans?repo_id=${REPO_ID}&limit=1")
        SCAN_ID=$(printf "%s" "$SCANS_JSON" | grep -o '"id":[0-9]*' | head -n1 | cut -d':' -f2)
    fi

    if [ -z "$SCAN_ID" ]; then
        printf "${RED}Error: Provide --scan-id <id> or --repo-id <id>.${NC}\n" >&2
        exit 1
    fi

    printf "${BLUE}==> Downloading SBOM for Scan ID %s...${NC}\n" "$SCAN_ID" >&2
    if [ -n "$OUTPUT" ]; then
        AUTH_HEADER=$(get_auth_header)
        curl -s -f -H "$AUTH_HEADER" "${VECTISPIRE_URL}/api/v1/scans/${SCAN_ID}/sbom" -o "$OUTPUT"
        printf "${GREEN}✔ SBOM saved to %s${NC}\n" "$OUTPUT" >&2
    else
        AUTH_HEADER=$(get_auth_header)
        curl -s -f -H "$AUTH_HEADER" "${VECTISPIRE_URL}/api/v1/scans/${SCAN_ID}/sbom"
    fi
}

# --- CLI Entrypoint ---

COMMAND="$1"
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
    sbom) cmd_sbom "$@" ;;
    version|--version|-v) printf "vectispire-cli v%s\n" "$VERSION" ;;
    *)
        printf "${RED}Unknown command: %s${NC}\n" "$COMMAND" >&2
        usage
        ;;
esac
