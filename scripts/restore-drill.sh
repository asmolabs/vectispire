#!/usr/bin/env bash
#
# The restore drill: proves a backup can be restored, and that the audit mirror still
# witnesses what the restore lost.
#
# **Why a drill and not a document.** A backup procedure nobody has executed is a belief.
# `docs/en/BACKUP_AND_RESTORE.md` says what to do; this says it works, on a real MySQL, with
# the image that ships. It is the same reasoning as `integrationTestAll`: an untested restore
# is discovered to be broken at the only moment it matters.
#
# **What it actually establishes**, which is more than "the dump loads":
#
#   1. A `mysqldump` taken from a live control plane restores into an empty engine, and the
#      application boots against it and serves.
#   2. The integrity chain survives the restore intact — a restored table is not a tampered one.
#   3. **The mirror still reports what the restore lost.** This is the point. The audit mirror
#      exists to be independent of the table; a backup that snapshots both and restores both
#      together destroys that independence, and the two then agree by construction. Here the
#      table goes back in time and the mirror does not, and `missingFromTable` equals exactly
#      the number of audited actions that happened after the dump.
#   4. And the mutation: with an **empty** mirror the same restore reports `missingFromTable: 0`
#      — indistinguishable from a clean restore. An operator who restores the mirror alongside
#      the database has thrown away the only witness that could have told them what was lost,
#      and has been given a green light for it. The drill fails if that case does not report 0,
#      because then assertion 3 was measuring something else.
#
# **A named gap.** The drill does not cover `ENCRYPTION_KEY`. It is in neither volume, so a
# byte-perfect restore of both, without it, gives a database whose encrypted columns cannot be
# read — and it boots and serves, which is what makes it dangerous. Asserting that here would
# mean asserting how the application behaves on an unreadable column, which is a separate
# question; §4 of the runbook covers it as a procedure with a human in it. Not covered is not
# the same as not important: this is the failure mode most likely to end a company.
#
# **It never touches a deployment.** Every container, network and volume it creates carries the
# `drill-` prefix, and it refuses to run if that prefix is empty. It does not read, write, mount
# or remove `vectispire_mysql_data` or `vectispire_audit`.
#
# Usage:
#   scripts/restore-drill.sh                          # needs vectispire:latest locally
#   VECTISPIRE_IMAGE=vectispire:1.2.3 scripts/restore-drill.sh
#   KEEP=1 scripts/restore-drill.sh                   # leave the containers up to poke at

set -euo pipefail

PREFIX="drill"
[ -n "$PREFIX" ] || { echo "refusing to run without a name prefix: it is the only thing keeping this off a deployment" >&2; exit 1; }

IMAGE="${VECTISPIRE_IMAGE:-vectispire:latest}"
MYSQL_IMAGE="${MYSQL_IMAGE:-mysql:8}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.11.1}"

NET="${PREFIX}-net"
DB_ORIGIN="${PREFIX}-db-origin"
DB_RESTORED="${PREFIX}-db-restored"
APP_ORIGIN="${PREFIX}-app-origin"
APP_RESTORED="${PREFIX}-app-restored"
APP_BLIND="${PREFIX}-app-blind"
MIRROR_VOL="${PREFIX}-mirror"
BLIND_VOL="${PREFIX}-mirror-empty"

# Not a secret, and it must not look like one: the drill's database is created and destroyed
# inside this script. A real deployment's key comes from ENCRYPTION_KEY_FILE — see the runbook.
DRILL_KEY="ZHJpbGwta2V5LW5vdC1hLXNlY3JldC0zMmJ5dGVz"
BOOTSTRAP_PASSWORD="AdminVectispire2026!"
ROTATED_PASSWORD="DrillVectispire2026!"
MIRROR_PATH="/var/lib/vectispire/audit/audit.ndjson"
WORK="$(mktemp -d)"

log()  { printf '\n\033[1m── %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local code=$?
  if [ "${KEEP:-}" = "1" ] && [ "$code" != 0 ]; then
    echo "KEEP=1 — leaving $APP_ORIGIN $APP_RESTORED $APP_BLIND $DB_ORIGIN $DB_RESTORED up"
    return
  fi
  for c in "$APP_BLIND" "$APP_RESTORED" "$APP_ORIGIN" "$DB_RESTORED" "$DB_ORIGIN"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker volume rm "$MIRROR_VOL" "$BLIND_VOL" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# `--network container:<name>` rather than a published port: the container under test and this
# shell do not share `localhost`, and publishing would collide with a running deployment.
api() {
  local container="$1"; shift
  docker run --rm --network "container:${container}" "$CURL_IMAGE" -s "$@"
}

wait_for_db() {
  local name="$1"
  for attempt in $(seq 1 120); do
    if docker run --rm --network "$NET" "$MYSQL_IMAGE" \
         mysqladmin ping -h "$name" -u vectispire -pvectispire --silent >/dev/null 2>&1; then
      echo "  $name ready after ${attempt}s"; return 0
    fi
    sleep 1
  done
  docker logs --tail 60 "$name" || true
  fail "$name never became reachable"
}

wait_for_app() {
  local name="$1"
  for attempt in $(seq 1 150); do
    if api "$name" -f -o /dev/null "http://localhost:3180/actuator/health" 2>/dev/null; then
      echo "  $name healthy after ${attempt}s"; return 0
    fi
    sleep 1
  done
  docker logs --tail 120 "$name" || true
  fail "$name never became healthy"
}

start_db() {
  docker run -d --name "$1" --network "$NET" \
    -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=vectispire \
    -e MYSQL_USER=vectispire -e MYSQL_PASSWORD=vectispire "$MYSQL_IMAGE" >/dev/null
  wait_for_db "$1"
}

# The mirror volume is a *parameter* here, which is the whole reason the mutation in phase 6
# costs one argument instead of a second script.
start_app() {
  local name="$1" db="$2" volume="$3"
  docker run -d --name "$name" --network "$NET" \
    -v "${volume}:/var/lib/vectispire/audit" \
    -e VECTISPIRE_DB_URL="jdbc:mysql://${db}:3306/vectispire" \
    -e VECTISPIRE_DB_USER=vectispire \
    -e VECTISPIRE_DB_PASSWORD=vectispire \
    -e ENCRYPTION_KEY="$DRILL_KEY" \
    -e VECTISPIRE_BOOTSTRAP_USERNAME=admin \
    -e VECTISPIRE_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" \
    -e VECTISPIRE_AUDIT_MIRROR="$MIRROR_PATH" \
    -e VECTISPIRE_EMBEDDED_WORKER=false \
    "$IMAGE" >/dev/null
  wait_for_app "$name"
}

# JSON `null` becomes the empty string, not the word "None": every assertion below tests a
# field for emptiness, and Python's repr of None is six characters that are not empty.
json() { python3 -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else v)' "$1"; }

# The bootstrap account is created with `mustChangePassword`, so the first token cannot read a
# guarded route. Rotating revokes every session the account had — including the one that made
# the change — so the sign-in is repeated after it. Same shape as the browser suite's helper.
sign_in() {
  local app="$1" body token must
  body=$(api "$app" -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$BOOTSTRAP_PASSWORD\"}" \
    "http://localhost:3180/api/v1/auth/login")
  token=$(printf '%s' "$body" | json token)
  must=$(printf '%s' "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("user",{}).get("mustChangePassword",False))')

  if [ -z "$token" ]; then
    body=$(api "$app" -X POST -H 'Content-Type: application/json' \
      -d "{\"username\":\"admin\",\"password\":\"$ROTATED_PASSWORD\"}" \
      "http://localhost:3180/api/v1/auth/login")
    token=$(printf '%s' "$body" | json token)
    [ -n "$token" ] || fail "neither the bootstrap nor the rotated password was accepted on $app"
    printf '%s' "$token"; return
  fi

  if [ "$must" = "True" ]; then
    api "$app" -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
      -d "{\"current_password\":\"$BOOTSTRAP_PASSWORD\",\"new_password\":\"$ROTATED_PASSWORD\"}" \
      -o /dev/null "http://localhost:3180/api/v1/auth/change-password"
    body=$(api "$app" -X POST -H 'Content-Type: application/json' \
      -d "{\"username\":\"admin\",\"password\":\"$ROTATED_PASSWORD\"}" \
      "http://localhost:3180/api/v1/auth/login")
    token=$(printf '%s' "$body" | json token)
    [ -n "$token" ] || fail "the rotated password was refused right after being set"
  fi
  printf '%s' "$token"
}

verify() {
  local app="$1" token="$2"
  api "$app" -H "Authorization: Bearer $token" "http://localhost:3180/api/v1/audit-log/verify"
}

field() { printf '%s' "$1" | json "$2"; }

# A *failed* sign-in is the cheapest audited action there is: it writes LOGIN_FAILURE to the
# table and the mirror, needs no token, and changes nothing else. Using a real operation would
# make the drill's assertion depend on that operation's own correctness.
audited_actions() {
  local app="$1" count="$2"
  for _ in $(seq 1 "$count"); do
    api "$app" -X POST -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"deliberately-wrong-for-the-drill"}' \
      -o /dev/null "http://localhost:3180/api/v1/auth/login" || true
  done
}

# ─────────────────────────────────────────────────────────────────────────────

log "0. the drill's own hygiene"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "$IMAGE not present — build it with ./gradlew :vectispire-core:jibDockerBuild"
for protected in vectispire_mysql_data vectispire_audit; do
  case "$MIRROR_VOL $BLIND_VOL" in
    *"$protected"*) fail "the drill would have touched $protected" ;;
  esac
done
echo "  image $IMAGE present; no deployment volume is in scope"

docker network create "$NET" >/dev/null

log "1. a live control plane with an independent audit mirror"
start_db "$DB_ORIGIN"
docker volume create "$MIRROR_VOL" >/dev/null
start_app "$APP_ORIGIN" "$DB_ORIGIN" "$MIRROR_VOL"
TOKEN=$(sign_in "$APP_ORIGIN")
BEFORE=$(verify "$APP_ORIGIN" "$TOKEN")
echo "  $BEFORE"
[ "$(field "$BEFORE" mirrored)" = "True" ] || fail "the mirror is not configured — the drill would prove nothing"
[ -z "$(field "$BEFORE" broken)" ] || fail "the chain was already broken before the drill did anything"
TOTAL_BEFORE=$(field "$BEFORE" total)

log "2. the dump — taken from the running engine, as an operator would"
docker exec "$DB_ORIGIN" sh -c \
  'exec mysqldump -u vectispire -pvectispire --single-transaction --routines --triggers vectispire' \
  > "$WORK/vectispire.sql" 2>/dev/null
[ -s "$WORK/vectispire.sql" ] || fail "the dump is empty"
echo "  $(wc -l < "$WORK/vectispire.sql" | tr -d ' ') lines, $(du -h "$WORK/vectispire.sql" | cut -f1)"

log "3. audited actions that happen AFTER the dump — what a restore will lose"
POST_DUMP=5
audited_actions "$APP_ORIGIN" "$POST_DUMP"
AFTER=$(verify "$APP_ORIGIN" "$TOKEN")
TOTAL_AFTER=$(field "$AFTER" total)
GREW=$(( TOTAL_AFTER - TOTAL_BEFORE ))
[ "$GREW" -eq "$POST_DUMP" ] || fail "expected $POST_DUMP new audit entries after the dump, the table grew by $GREW"
echo "  $GREW entries written after the dump, and the mirror has them all"

log "4. restored into an empty engine, with the live mirror kept in place"
start_db "$DB_RESTORED"
docker exec -i "$DB_RESTORED" sh -c \
  'exec mysql -u vectispire -pvectispire vectispire' < "$WORK/vectispire.sql" 2>/dev/null \
  || fail "the dump did not load"
docker rm -f "$APP_ORIGIN" >/dev/null
start_app "$APP_RESTORED" "$DB_RESTORED" "$MIRROR_VOL"
RTOKEN=$(sign_in "$APP_RESTORED")
RESTORED=$(verify "$APP_RESTORED" "$RTOKEN")
echo "  $RESTORED"

log "5. what the restore is allowed to say, and what it must not"
[ -z "$(field "$RESTORED" broken)" ] \
  || fail "the chain reports a break after the restore: $(field "$RESTORED" broken)"
echo "  the integrity chain survived the restore — a restored table is not a tampered one"

MISSING=$(field "$RESTORED" missingFromTable)
[ "$MISSING" -ge "$POST_DUMP" ] \
  || fail "the mirror reports $MISSING entries missing from the restored table; at least $POST_DUMP were written after the dump. The witness is not witnessing."
echo "  the mirror reports $MISSING entries the restored table no longer has — the $POST_DUMP lost, and the drill's own sign-ins"

[ "$(field "$RESTORED" intact)" = "False" ] \
  || fail "the restore reports intact:true while the mirror holds entries the table lost — that is a green light over a data loss"
echo "  intact:false, correctly: the chain holding is not the whole answer"

log "6. the mutation — the same restore, with the mirror thrown away"
docker volume create "$BLIND_VOL" >/dev/null
docker rm -f "$APP_RESTORED" >/dev/null
start_app "$APP_BLIND" "$DB_RESTORED" "$BLIND_VOL"
BTOKEN=$(sign_in "$APP_BLIND")
BLIND=$(verify "$APP_BLIND" "$BTOKEN")
echo "  $BLIND"
BMISSING=$(field "$BLIND" missingFromTable)
[ "$BMISSING" -eq 0 ] \
  || fail "an empty mirror still reported $BMISSING missing — then phase 5 was not measuring the mirror"
echo "  missingFromTable:0 — the data loss has become invisible, and this is the point:"
echo "  restoring the mirror alongside the database is how you get a green light over it."

# **The sharper half.** `intact` is `broken == null && missingFromTable == 0` by design, because
# `missingFromMirror` has innocent explanations (rows predating the mirror, a full disk) and an
# integrity alarm that cries wolf is one nobody reads. But it means the blind restore reports
# `intact: true` while the *other* counter is shouting. That is the number an operator has to read
# after a restore, and the reason §5 of the runbook gives it a sentence of its own.
[ "$(field "$BLIND" intact)" = "True" ] \
  || fail "the blind restore did not report intact:true — the hazard this drill pins has changed shape, and the runbook now describes something else"
BMIRROR=$(field "$BLIND" missingFromMirror)
[ "$BMIRROR" -ge "$POST_DUMP" ] \
  || fail "the emptied mirror reports only $BMIRROR entries missing; the table holds at least $POST_DUMP it never saw"
echo "  and yet intact:true, with missingFromMirror:$BMIRROR — the signal exists, in the counter"
echo "  that intact does not read. After a restore, read both."

log "the drill passed"
cat <<'SUMMARY'
  A dump taken from a live engine restores and serves.
  The integrity chain survives the restore.
  The mirror reports what the restore lost — and reports nothing once it is restored too.

  Not covered, deliberately: ENCRYPTION_KEY. It is in neither volume. See §4 of
  docs/en/BACKUP_AND_RESTORE.md, which is a procedure with a human in it.
SUMMARY
