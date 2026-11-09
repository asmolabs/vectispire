#!/usr/bin/env bash
# A SQL session on the load test's own MySQL — never the operator's, never the test suites'.
#   load/sql.sh "select count(*) from t_issue"      or      load/sql.sh < file.sql
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${LOAD_STATE_DIR:-$HERE/.state}"
NAME="vectispire-loadtest-${LOAD_ENGINE:-mysql9}"
if [ $# -gt 0 ]; then
  docker exec -i "$NAME" mysql -uroot -p"$(cat "$STATE/db_root_password")" --table vectispire -e "$*" 2>&1 | grep -v "Using a password"
else
  docker exec -i "$NAME" mysql -uroot -p"$(cat "$STATE/db_root_password")" --table vectispire 2>&1 | grep -v "Using a password"
fi
