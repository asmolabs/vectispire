#!/usr/bin/env bash
# Times each route of the scenario alone, one call at a time, on a quiet server: the unloaded cost,
# against which a level's latencies read. `load/probe.sh [route-regex]`
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${LOAD_STATE_DIR:-$HERE/.state}"
BASE="${BASE:-http://127.0.0.1:${LOAD_APP_PORT:-3190}}"
FILTER="${1:-.}"
seed() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$STATE/seed.json" "$1"; }
PASSWORD="$(seed 'd["password"]')"
token() { curl -fsS -XPOST "$BASE/api/v1/auth/login" -H 'content-type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$PASSWORD\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
ADMIN="$(token ada.admin)"
READER="$(token reader.00)"
REPO="$(seed '[t for t in d["targets"] if t["kind"]=="repository"][0]["id"]')"
GATE_REPO="$(seed 'd["gate_keys"][0]["repository_id"]')"
GATE_KEY="$(seed 'd["gate_keys"][0]["secret"]')"
ISSUE="$(curl -fsS "$BASE/api/v1/issues?state=open&limit=1" -H "Authorization: Bearer $ADMIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["items"][0]["id"])')"

time_it() {
  local name="$1" tok="$2" path="$3"; shift 3
  [[ "$name" =~ $FILTER ]] || return 0
  local out
  out="$(for _ in 1 2 3; do curl -s -o /dev/null -w '%{http_code} %{time_total}\n' -H "Authorization: Bearer $tok" "$@" "$BASE$path"; done)"
  printf '%-26s %s\n' "$name" "$(echo "$out" | awk '{c=$1; t[NR]=$2*1000} END {printf "%s  %6.0f %6.0f %6.0f ms", c, t[1], t[2], t[3]}')"
}

echo "route                      code  1st    2nd    3rd"
time_it issues_admin "$ADMIN" "/api/v1/issues?state=open&limit=50"
time_it issues_admin_filtered "$ADMIN" "/api/v1/issues?state=open&severity=high&type=vulnerability&limit=50"
time_it issues_admin_search "$ADMIN" "/api/v1/issues?state=open&search=CVE-2024&limit=50"
time_it issues_admin_deep_page "$ADMIN" "/api/v1/issues?state=open&limit=50&offset=50000"
time_it issues_reader "$READER" "/api/v1/issues?state=open&limit=50"
time_it issues_reader_filtered "$READER" "/api/v1/issues?state=open&severity=high&limit=50"
time_it issue_detail "$ADMIN" "/api/v1/issues/$ISSUE"
time_it dashboard "$ADMIN" "/api/v1/dashboard"
time_it dashboard_reader "$READER" "/api/v1/dashboard"
time_it dashboard_trends "$ADMIN" "/api/v1/dashboard/trends?days=30"
time_it posture_analytics "$ADMIN" "/api/v1/dashboard/posture-analytics?days=30"
time_it security_overview "$ADMIN" "/api/v1/security/overview"
time_it scorecards_global "$ADMIN" "/api/v1/scorecards/global"
time_it scorecard_repository "$ADMIN" "/api/v1/scorecards/repositories/$REPO"
time_it repositories "$ADMIN" "/api/v1/repositories?limit=50"
time_it repositories_reader "$READER" "/api/v1/repositories?limit=50"
time_it containers "$ADMIN" "/api/v1/containers?limit=100"
time_it scans "$ADMIN" "/api/v1/scans?limit=50"
time_it inventory_search "$ADMIN" "/api/v1/inventory/search?name=cor"
time_it licenses_summary "$ADMIN" "/api/v1/licenses/summary"
time_it licenses_inventory "$ADMIN" "/api/v1/licenses/inventory?limit=100"
time_it owasp_coverage "$ADMIN" "/api/v1/owasp/coverage"
time_it remediation_debt "$ADMIN" "/api/v1/remediation/debt"
time_it export_csv "$ADMIN" "/api/v1/targets/repository/$REPO/issues.csv"
time_it gate "$GATE_KEY" "/api/v1/gate" -XPOST -H 'content-type: application/json' \
  -d "{\"repository_id\":$GATE_REPO,\"fail_on_severity\":\"critical\"}"
