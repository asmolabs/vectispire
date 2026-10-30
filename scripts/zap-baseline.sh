#!/usr/bin/env bash
#
# The OWASP ZAP baseline scan of a running control plane: the interface and `/api/v1`, signed in.
#
# **Why it exists.** Every other check reads Vectispire — its code, its dependencies, its images,
# its contract. None had ever spoken HTTP to the running application the way a stranger does, so
# what the server actually answers — headers, cookies, error bodies, caching, what the shell of the
# interface discloses — was asserted route by route in tests and never looked at as a whole.
#
# **Passive only.** The baseline spiders and reads the answers; it does not attack. The API reaches
# the sites tree through `ci/zap/hook.py`, which imports the contract's GET operations only — the
# reason is written there. An active scan writes, and belongs on a disposable instance with a
# reviewer watching, not in a nightly.
#
# **What it refuses.** A medium or high alert that `ci/zap/accepted-alerts.txt` does not cover for
# that path, and a run that saw too little to be believed (`ci/zap/gate.py`).
#
# **It never touches a deployment.** Every container and network carries the `zap-` prefix, and the
# database is a fresh one destroyed on exit.
#
# Usage:
#   scripts/zap-baseline.sh                          # needs vectispire:latest locally
#   VECTISPIRE_IMAGE=vectispire:nightly scripts/zap-baseline.sh
#   REPORT_DIR=./zap-report scripts/zap-baseline.sh  # keep the reports (the nightly uploads them)
#   KEEP=1 scripts/zap-baseline.sh                   # leave the containers up after a failure

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${ZAP_PREFIX-zap}"
[ -n "$PREFIX" ] || { echo "refusing to run without a name prefix: it is the only thing keeping this off a deployment" >&2; exit 1; }

IMAGE="${VECTISPIRE_IMAGE:-vectispire:latest}"
# **By the digest of its multi-architecture index**, as every other image here (`dockerfile-policy`):
# `stable` is whatever ZAP released last, and a rule added overnight would turn the nightly red with
# nothing in this repository having changed. Moved by hand — Dependabot reads no shell script — with
# a run of this script, which shows the alerts the new rules raise before the nightly does.
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93}"

# The shipped composition's MySQL, read from `docker-compose.yml` exactly as the restore drill reads
# it: the scan looks at the server an installation runs, and a fallback to a tag would not be that.
MYSQL_IMAGE="$(sed -n 's/^[[:space:]]*image:[[:space:]]*\(mysql:[^[:space:]#]*\).*$/\1/p' "$ROOT/docker-compose.yml")"
printf '%s\n' "$MYSQL_IMAGE" | grep -Eqx 'mysql:[0-9][0-9.]*@sha256:[0-9a-f]{64}' \
  || { echo "docker-compose.yml's MySQL [$MYSQL_IMAGE] is not one mysql:<version>@sha256:<digest> line" >&2; exit 1; }

NET="${PREFIX}-net"
DB="${PREFIX}-db"
APP="${PREFIX}-app"
TARGET="http://${APP}:3180"

# Not secrets, and they must not look like ones: the database is created and destroyed here.
SCAN_KEY="emFwLWJhc2VsaW5lLWtleS1ub3QtYS1zZWNyZXQtMzI=" # gitleaks:allow — invented: "zap-baseline-key-not-a-secret-32"
BOOTSTRAP_PASSWORD="AdminVectispire2026!"
ROTATED_PASSWORD="ZapBaseline2026!"

WORK="$(mktemp -d)"
REPORT_DIR="${REPORT_DIR:-$WORK/report}"
mkdir -p "$REPORT_DIR"

log()  { printf '\n\033[1m── %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local code=$?
  if [ "${KEEP:-}" = "1" ] && [ "$code" != 0 ]; then
    echo "KEEP=1 — leaving $APP $DB up"
    return
  fi
  if [ "$code" != 0 ]; then
    echo "═══ $APP, last 60 lines"; docker logs --tail 60 "$APP" 2>&1 || true
  fi
  docker rm -f "$APP" "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Sessions and passwords travel on stdin as a curl config, never as arguments `ps` would show —
# the restore drill's `api`, `bearer` and `body`, for the same reason.
api() { docker run -i --rm --network "container:${APP}" "$CURL_IMAGE" -s -K - "$@"; }
cfg_quote() { local s="${1//\\/\\\\}"; printf '"%s"' "${s//\"/\\\"}"; }
bearer() { printf 'header = %s\n' "$(cfg_quote "Authorization: Bearer $1")"; }
body()   { printf 'data-raw = %s\n' "$(cfg_quote "$1")"; }
json()   { python3 -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else v)' "$1"; }

login() {
  body "{\"username\":\"admin\",\"password\":\"$1\"}" \
    | api -X POST -H 'Content-Type: application/json' "http://localhost:3180/api/v1/auth/login" | json token
}

log "0. hygiene"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "$IMAGE not present — docker build -f Dockerfile -t $IMAGE ."
echo "  scanning $IMAGE on $MYSQL_IMAGE with $ZAP_IMAGE"

log "1. a control plane on a fresh MySQL"
docker network create "$NET" >/dev/null
MYSQL_ROOT_PASSWORD=root MYSQL_PASSWORD=vectispire \
docker run -d --name "$DB" --network "$NET" \
  -e MYSQL_ROOT_PASSWORD -e MYSQL_DATABASE=vectispire -e MYSQL_USER=vectispire -e MYSQL_PASSWORD \
  "$MYSQL_IMAGE" >/dev/null
for attempt in $(seq 1 120); do
  docker exec "$DB" mysqladmin ping -h "$DB" --silent >/dev/null 2>&1 && break
  [ "$attempt" = 120 ] && { docker logs --tail 60 "$DB"; fail "the database never became reachable"; }
  sleep 1
done
VECTISPIRE_DB_PASSWORD=vectispire ENCRYPTION_KEY="$SCAN_KEY" VECTISPIRE_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" \
docker run -d --name "$APP" --network "$NET" \
  -e VECTISPIRE_DB_URL="jdbc:mysql://${DB}:3306/vectispire" \
  -e VECTISPIRE_DB_USER=vectispire -e VECTISPIRE_DB_PASSWORD -e ENCRYPTION_KEY \
  -e VECTISPIRE_BOOTSTRAP_USERNAME=admin -e VECTISPIRE_BOOTSTRAP_PASSWORD \
  -e VECTISPIRE_EMBEDDED_WORKER=false \
  "$IMAGE" >/dev/null
for attempt in $(seq 1 180); do
  api -f -o /dev/null "http://localhost:3180/actuator/health" </dev/null 2>/dev/null && { echo "  healthy after ${attempt}s"; break; }
  [ "$attempt" = 180 ] && fail "the control plane never became healthy"
  sleep 1
done

log "2. signed in, past the forced password change"
# The bootstrap account must change its password before a guarded route answers, and the change
# revokes every session the account had — so the scan's session is the one taken after it.
TOKEN="$(login "$BOOTSTRAP_PASSWORD")"
[ -n "$TOKEN" ] || fail "the bootstrap password was refused"
{ bearer "$TOKEN"; body "{\"current_password\":\"$BOOTSTRAP_PASSWORD\",\"new_password\":\"$ROTATED_PASSWORD\"}"; } \
  | api -X POST -H 'Content-Type: application/json' -o /dev/null -f "http://localhost:3180/api/v1/auth/change-password" \
  || fail "the password change was refused"
TOKEN="$(login "$ROTATED_PASSWORD")"
[ -n "$TOKEN" ] || fail "the new password was refused right after being set"
bearer "$TOKEN" | api -f -o /dev/null "http://localhost:3180/api/v1/auth/me" || fail "the session does not read /auth/me"
echo "  session accepted on /api/v1/auth/me"

log "3. the baseline"
python3 - "$ROOT/vectispire-angular/openapi.json" "$WORK/openapi-get.json" <<'PY'
import json, sys
spec = json.load(open(sys.argv[1]))
spec['paths'] = {p: {'get': ops['get'], **({'parameters': ops['parameters']} if 'parameters' in ops else {})}
                 for p, ops in spec['paths'].items() if 'get' in ops}
json.dump(spec, open(sys.argv[2], 'w'))
print(f"  {len(spec['paths'])} GET operations handed to ZAP")
PY
cp "$ROOT/ci/zap/hook.py" "$WORK/"
# ZAP runs as uid 1000 and writes its reports and `seen.json` here; the runner's user is another.
chmod 0777 "$WORK"
set +e
# `-I`: the baseline's own verdict is per rule, and the gate below is the verdict (gate.py says why).
# `-j`: the AJAX spider drives a browser through the interface, which the classic spider cannot.
# The session reaches ZAP as `ZAP_AUTH_HEADER_VALUE`, by name from this environment, and is added to
# requests for the control plane's host only. **The host name alone, without the port**: ZAP compares
# it with the request's host name, and `zap-app:3180` matched nothing — the first run sent no session
# at all, answered 401 on every guarded route, and only the gate's count of 2xx answers said so.
ZAP_AUTH_HEADER_VALUE="Bearer $TOKEN" \
docker run --rm --name "${PREFIX}-scanner" --network "$NET" \
  -v "$WORK:/zap/wrk:rw" \
  -e ZAP_AUTH_HEADER_VALUE -e ZAP_AUTH_HEADER=Authorization -e ZAP_AUTH_HEADER_SITE="${APP}" \
  -e ZAP_TARGET="$TARGET" \
  "$ZAP_IMAGE" zap-baseline.py -t "$TARGET" -I -j -m 2 \
    --hook=/zap/wrk/hook.py -J report.json -r report.html -w report.md
zap=$?
set -e
# 0 clean, 1 a FAIL rule, 2 a WARN rule, 3 ZAP itself failed. With `-I`, only 3 means no verdict.
[ "$zap" -le 2 ] || fail "zap-baseline.py exited $zap: the scan did not complete"
[ -s "$WORK/report.json" ] || fail "ZAP wrote no report"
[ -s "$WORK/seen.json" ] || fail "the hook wrote no record of what the scan saw"
cp "$WORK/report.json" "$WORK/report.html" "$WORK/report.md" "$WORK/seen.json" "$REPORT_DIR/" 2>/dev/null || true

log "4. the verdict"
python3 "$ROOT/ci/zap/gate.py" "$WORK/report.json" "$WORK/seen.json" "$ROOT/ci/zap/accepted-alerts.txt"
