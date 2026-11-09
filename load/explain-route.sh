#!/usr/bin/env bash
# The statements one call of a route runs, and what each cost: performance_schema's digests, reset
# before the call. For finding what a slow route spends its time on.
#   load/explain-route.sh /api/v1/dashboard [user] [curl options…]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${LOAD_STATE_DIR:-$HERE/.state}"
BASE="${BASE:-http://127.0.0.1:${LOAD_APP_PORT:-3190}}"
DB="vectispire-loadtest-${LOAD_ENGINE:-mysql9}"
path="$1"; user="${2:-ada.admin}"; shift; [ $# -gt 0 ] && shift
PASSWORD="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$STATE/seed.json")"
if [[ "$user" == key:* ]]; then
  TOKEN="${user#key:}"
else
  TOKEN="$(curl -fsS -XPOST "$BASE/api/v1/auth/login" -H 'content-type: application/json' \
    -d "{\"username\":\"$user\",\"password\":\"$PASSWORD\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
fi
sql() { docker exec -i "$DB" mysql -uroot -p"$(cat "$STATE/db_root_password")" vectispire --table -e "$1" 2>/dev/null; }
# Once warm, so the first call's caches do not decide what is read.
curl -s -o /dev/null -H "Authorization: Bearer $TOKEN" "$@" "$BASE$path"
sql "truncate table performance_schema.events_statements_summary_by_digest"
curl -s -o /dev/null -w 'status %{http_code}, %{time_total}s, %{size_download} bytes\n' -H "Authorization: Bearer $TOKEN" "$@" "$BASE$path"
sql "select count_star calls, round(sum_timer_wait/1e9) total_ms, sum_rows_examined rows_exam, sum_rows_sent rows_sent,
            left(regexp_replace(digest_text, '[[:space:]]+', ' '), ${WIDTH:-300}) statement
     from performance_schema.events_statements_summary_by_digest where schema_name='vectispire'
     order by sum_timer_wait desc limit ${TOP:-15}"
