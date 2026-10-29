#!/usr/bin/env bash
#
# The upgrade drill: the last published release writes real data, the control plane built from
# this commit starts on the same database and reads it back unchanged.
#
# **Why a drill and not a migration test.** `integrationTestAll` applies every migration to an
# empty schema and checks the entities agree with the result. What it never does is the thing an
# operator does: start the new image on a database the previous one has been living in. A
# migration that adds a NOT NULL column without a default passes on an empty table and refuses
# to start on the first installation that has a row in it; a backfill that is wrong is invisible
# on zero rows. `docs-site/getting-started/installation.md` says migrations "have no way back" —
# this is the check that the way forward exists, for the step every installation takes next.
#
# **What it establishes**, on one engine per run (ENGINE=mysql or ENGINE=postgresql):
#
#   1. The previous release (the newest `v*` tag, release candidates included, at the digest the
#      registry serves for it, its signature verified with cosign against that tag's release
#      workflow before it is pulled) migrates an empty schema and serves.
#   2. Through its API, rows that migrations will meet: the bootstrap account's password changed,
#      a second account, a solution and a project, a repository target, settings, the webhook
#      signing secret, an API key, and the audit trail all of that writes.
#   3. The image built from this commit starts on that database and becomes healthy. That is the
#      schema proof: Flyway applies what is new and validates the checksums of what is not, and
#      Hibernate runs with `ddl-auto: validate` — any disagreement between the entities and the
#      migrated schema stops the context, and health never answers.
#   4. Every applied migration succeeded, and the schema version did not go backwards.
#   5. What was written is read back identically: every field the previous release returned for
#      those objects is returned with the same value (fields the new release adds are allowed —
#      the API is additive, decision 0043 §1). The session the previous release issued is still
#      valid, the rotated password signs in, the API key authenticates, the audit chain verifies
#      across the upgrade. A migration that rewrites a value on purpose is declared, with its
#      reason, in `ci/upgrade/accepted-rewrites.txt` — a list that is empty at every release.
#      Run from v0.10.0 on 2026-10-14, the drill found exactly one: V70's stamp of
#      `lastScheduledScanAt` on targets with no schedule, which the release notes announce.
#   6. The new release writes too: a second repository, whose id follows the first — an engine
#      sequence left behind by a migration fails here, not at a customer's first click.
#
# **What it does not establish.** Whether a scan survives the upgrade (no scanner runs here), nor
# the agent of the previous release against the new control plane — that is decision 0043 §2's
# test, a different one (`ci.yml`'s `previous-agent`), which resolves and verifies its image with the
# same `scripts/release-image.sh`. And when no migration was added since the tag, step 3 applies
# nothing new: the drill then proves the path and the data, not a migration. The output says which.
#
# **It never touches a deployment.** Every container and network it creates carries the
# `vs-up-` prefix; it mounts no volume and publishes no port.
#
# Usage:
#   scripts/upgrade-drill.sh                                    # mysql, needs vectispire:latest
#   ENGINE=postgresql scripts/upgrade-drill.sh
#   TO_IMAGE=vectispire:verify FROM_TAG=v0.10.0 scripts/upgrade-drill.sh
#   FROM_TAG=v0.10.0 FROM_IMAGE=ghcr.io/asmolabs/vectispire@sha256:… scripts/upgrade-drill.sh
#   KEEP=1 scripts/upgrade-drill.sh                             # leave the containers up on failure

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

PREFIX="vs-up"
[ -n "$PREFIX" ] || { echo "refusing to run without a name prefix: it is the only thing keeping this off a deployment" >&2; exit 1; }

ENGINE="${ENGINE:-mysql}"
TO_IMAGE="${TO_IMAGE:-vectispire:latest}"
# By the digest of its multi-architecture index, as `restore-drill.sh` names it.
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93}"
# Values a migration since the release rewrites on purpose, each with its reason (see the file).
REWRITES="ci/upgrade/accepted-rewrites.txt"
# Generous: on a developer's arm64 machine the release image (amd64 only) runs emulated, and a
# Spring context under emulation takes minutes. On the runner it is native and takes seconds.
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-420}"

# The engines the integration campaign runs (`Engine.java`): one pin in several places, and a
# difference would be an upgrade checked on a server nothing else checks. Hence MySQL 9.4 and not
# the composition's 8.4, which `restore-drill.sh` runs — between them the nightly drills both lines,
# and neither is meant to follow the other. Here each is named by the patch the campaign's tag
# resolved to on 2026-10-15 and its multi-architecture index digest, as are `ci.yml`'s and
# `nightly.yml`'s MySQL services: a tag the registry republishes is a different server on a
# different night, and the drill would report the release for it. **Nothing moves these for us** — Dependabot reads neither
# a script nor a workflow's `services:` — so a change of `Engine.java` moves them by hand, resolved
# with `docker buildx imagetools inspect <image:tag>`, the index and not one platform's manifest.
# `scripts/check-db-pins.py` (`docs-consistency`) holds them together: a pin whose tag is not the
# campaign's tag or a patch of it fails the push, on either side of the move.
case "$ENGINE" in
  mysql)
    DB_IMAGE="${DB_IMAGE:-mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2}"
    DB_URL="jdbc:mysql://${PREFIX}-${ENGINE}-db:3306/vectispire" ;;
  postgresql)
    DB_IMAGE="${DB_IMAGE:-postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94}"
    DB_URL="jdbc:postgresql://${PREFIX}-${ENGINE}-db:5432/vectispire" ;;
  *) echo "ENGINE must be mysql or postgresql, not [$ENGINE]" >&2; exit 1 ;;
esac

NET="${PREFIX}-${ENGINE}-net"
DB="${PREFIX}-${ENGINE}-db"
APP_FROM="${PREFIX}-${ENGINE}-from"
APP_TO="${PREFIX}-${ENGINE}-to"
CURL="${PREFIX}-${ENGINE}-curl"
# Not secrets, and they must not look like any: the database lives and dies inside this script.
DRILL_KEY="dXBncmFkZS1kcmlsbC1rZXktbm90LWEtc2VjcmV0LTI="  # gitleaks:allow — base64 of "upgrade-drill-key-not-a-secret-2", invented
DB_PASSWORD="vectispire-upgrade-drill"
BOOTSTRAP_PASSWORD="AdminVectispire2026!"
ROTATED_PASSWORD="UpgradeVectispire2026!"
ANALYST_PASSWORD="AnalystVectispire2026!"
WORK="$(mktemp -d)"
STARTED=$(date +%s)

log()  { printf '\n\033[1m── %s\033[0m  (%ss)\n' "$*" "$(( $(date +%s) - STARTED ))"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local code=$?
  if [ "$code" != 0 ]; then
    for c in "$APP_TO" "$APP_FROM"; do
      if docker inspect "$c" >/dev/null 2>&1; then
        echo "═══ $c, last 80 lines"; docker logs --tail 80 "$c" 2>&1 || true
      fi
    done
  fi
  if [ "${KEEP:-}" = "1" ] && [ "$code" != 0 ]; then
    echo "KEEP=1 — leaving $APP_FROM $APP_TO $DB $CURL up"
    return
  fi
  for c in "$CURL" "$APP_TO" "$APP_FROM" "$DB"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# One curl container on the drill's network for every call, rather than one per call: the control
# plane is addressed by the alias both releases carry in turn, and the shell shares no `localhost`
# with it. `-w` appends the status on its own line so a refusal cannot pass for a body. A failure
# names the URL (the last argument) and nothing of the request.
#
# **Sessions, keys and passwords travel on stdin, never as arguments.** `-H "Authorization: …"`
# and `-d '{"password":…}'` were arguments of `docker exec` on the host and of curl in its
# container, which `ps` shows to every user of either. `api` reads a curl config (`-K -`) from its
# stdin — `header` and `data-raw` lines, built by `bearer` and `body` below with `printf`, a shell
# builtin — so what stays on the command line is the method, the content type and the URL.
api() {
  local out status
  out=$(docker exec -i "$CURL" curl -s -K - -w '\n%{http_code}' "$@") || fail "curl could not reach ${!#}"
  status="${out##*$'\n'}"
  printf '%s' "${out%$'\n'*}"
  case "$status" in
    2??) ;;
    *) printf '\n' >&2; fail "HTTP $status on ${!#} — ${out%$'\n'*}" ;;
  esac
}
# A curl config value is double-quoted with backslash escapes; JSON bodies carry both characters.
cfg_quote() { local s="${1//\\/\\\\}"; printf '"%s"' "${s//\"/\\\"}"; }
bearer() { printf 'header = %s\n' "$(cfg_quote "Authorization: Bearer $1")"; }
# `data-raw`, not `data`: a body starting with `@` must never be read as a file name.
body()   { printf 'data-raw = %s\n' "$(cfg_quote "$1")"; }
get()  { bearer "$1" | api "http://app:3180$2"; }
send() { { bearer "$2"; body "$4"; } | api -X "$1" -H 'Content-Type: application/json' "http://app:3180$3"; }
# Signing in carries no credential header at all: an empty bearer is a malformed one.
login() {
  body "{\"username\":\"$1\",\"password\":\"$2\"}" \
    | api -X POST -H 'Content-Type: application/json' http://app:3180/api/v1/auth/login | json token
}

json() { python3 -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1].split("."): v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else v)' "$1"; }

# **The password is never an argument**, not even this throwaway one: `docker exec -e
# MYSQL_PWD=…` put it in the docker client's command line on the host, which every user of the
# host reads, and MySQL deprecates `MYSQL_PWD` besides. Both clients read it inside the container
# from the variable the server was created with: MySQL from an option file written by `printf`, a
# shell builtin, readable by its owner alone (`write_client_file`); PostgreSQL from `PGPASSWORD`,
# set by the container's shell and so in no argument list. The query is a positional parameter,
# never spliced into the script, so its quotes are its own.
CLIENT_FILE=/tmp/vs-up-client.cnf
write_client_file() {
  docker exec "$DB" sh -c 'umask 077
printf "[client]\nuser=%s\npassword=\"%s\"\n" "$MYSQL_USER" "$MYSQL_PASSWORD" > "$1"' sh "$CLIENT_FILE"
}
sql() {
  case "$ENGINE" in
    mysql) docker exec "$DB" sh -c 'exec mysql --defaults-extra-file="$1" -N -B vectispire -e "$2"' sh "$CLIENT_FILE" "$1" ;;
    postgresql) docker exec "$DB" sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U vectispire -d vectispire -At -F "$(printf "\t")" -c "$1"' sh "$1" ;;
  esac
}

# Flyway's own record, quoted per engine: `version` is a reserved word on neither, but MySQL and
# PostgreSQL disagree on what a boolean column prints as, so `success` is compared as a number.
schema_version() { sql 'SELECT version FROM flyway_schema_history WHERE version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1'; }
applied_count()  { sql 'SELECT COUNT(*) FROM flyway_schema_history'; }
failed_count()   {
  case "$ENGINE" in
    mysql) sql 'SELECT COUNT(*) FROM flyway_schema_history WHERE success = 0' ;;
    postgresql) sql 'SELECT COUNT(*) FROM flyway_schema_history WHERE NOT success' ;;
  esac
}

wait_for_db() {
  local deadline=$(( $(date +%s) + 180 ))
  until case "$ENGINE" in
          mysql) write_client_file 2>/dev/null && docker exec "$DB" sh -c 'exec mysql --defaults-extra-file="$1" -h 127.0.0.1 -e "SELECT 1" vectispire' sh "$CLIENT_FILE" >/dev/null 2>&1 ;;
          postgresql) docker exec "$DB" sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -h 127.0.0.1 -U vectispire -d vectispire -c "SELECT 1"' >/dev/null 2>&1 ;;
        esac; do
    [ "$(date +%s)" -lt "$deadline" ] || { docker logs --tail 60 "$DB" || true; fail "$DB never accepted a connection"; }
    sleep 1
  done
  echo "  $DB_IMAGE accepts connections"
}

# Health, not the port: the process listens before the context is up, and the context is where
# Flyway and the schema validation run. The container exiting is a verdict too, and an earlier one.
wait_for_app() {
  local name="$1" deadline=$(( $(date +%s) + HEALTH_TIMEOUT )) began
  began=$(date +%s)
  until docker exec "$CURL" curl -sf -o /dev/null http://app:3180/actuator/health 2>/dev/null; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]; then
      fail "$name exited before becoming healthy — the schema or the context refused to start"
    fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "$name was not healthy after ${HEALTH_TIMEOUT}s"
    sleep 2
  done
  echo "  $name healthy after $(( $(date +%s) - began ))s"
}

# A credential reaches a container as `-e NAME`, its value in the docker client's environment for
# that one command: `-e NAME=value` is an argument, which `ps` shows to every user of the host.
start_app() {
  local name="$1" image="$2"
  VECTISPIRE_DB_PASSWORD="$DB_PASSWORD" ENCRYPTION_KEY="$DRILL_KEY" \
  VECTISPIRE_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" \
  docker run -d --name "$name" --network "$NET" --network-alias app \
    -e VECTISPIRE_DB_URL="$DB_URL" \
    -e VECTISPIRE_DB_USER=vectispire \
    -e VECTISPIRE_DB_PASSWORD \
    -e ENCRYPTION_KEY \
    -e VECTISPIRE_BOOTSTRAP_USERNAME=admin \
    -e VECTISPIRE_BOOTSTRAP_PASSWORD \
    -e VECTISPIRE_EMBEDDED_WORKER=false \
    "$image" >/dev/null
  wait_for_app "$name"
}

# The objects the drill wrote, as the API returns them, reduced to what identifies them: the
# lists also hold what the application creates itself, which a new release may legitimately add to.
snapshot() {
  local token="$1" out="$2"
  {
    printf '{"repositories":'; get "$token" /api/v1/repositories
    printf ',"settings":'; get "$token" /api/v1/settings
    printf ',"webhook_secret":'; get "$token" /api/v1/settings/webhook-secret
    printf ',"api_keys":'; get "$token" /api/v1/api-keys
    printf ',"users":'; get "$token" /api/v1/users
    printf ',"solutions":'; get "$token" /api/v1/solutions
    printf '}'
  } > "$out"
}

# ─────────────────────────────────────────────────────────────────────────────

log "0. the two releases, and the drill's own hygiene"
[ -f "$REWRITES" ] || fail "$REWRITES is missing — an empty one accepts no rewrite, a missing one is a broken checkout"
docker image inspect "$TO_IMAGE" >/dev/null 2>&1 \
  || fail "$TO_IMAGE not present — build it from this commit (docker build -f Dockerfile -t $TO_IMAGE .)"
# The newest release reachable from this commit, by the digest the registry serves for it, its
# signature verified with cosign against that tag's release workflow before it is pulled — the rules
# and their reasons are `scripts/release-image.sh`'s, shared with the previous agent's check.
release="$(TAG="${FROM_TAG:-}" IMAGE="${FROM_IMAGE:-}" scripts/release-image.sh vectispire)" \
  || fail "the previous release's control plane could not be resolved and verified — not run"
FROM_TAG="${release%% *}"
FROM_IMAGE="${release#* }"
echo "  from  $FROM_TAG  $FROM_IMAGE"
echo "  to    $TO_IMAGE ($(docker image inspect -f '{{.Id}}' "$TO_IMAGE" | cut -c1-19))"
echo "  on    $ENGINE ($DB_IMAGE)"
docker pull -q "$CURL_IMAGE" >/dev/null 2>&1 || docker image inspect "$CURL_IMAGE" >/dev/null 2>&1 \
  || fail "$CURL_IMAGE cannot be pulled"

docker network create "$NET" >/dev/null
docker run -d --name "$CURL" --network "$NET" --entrypoint sleep "$CURL_IMAGE" 7200 >/dev/null

log "1. an empty $ENGINE, migrated by $FROM_TAG"
case "$ENGINE" in
  mysql)
    MYSQL_ROOT_PASSWORD="$DB_PASSWORD" MYSQL_PASSWORD="$DB_PASSWORD" \
    docker run -d --name "$DB" --network "$NET" \
      -e MYSQL_ROOT_PASSWORD -e MYSQL_DATABASE=vectispire \
      -e MYSQL_USER=vectispire -e MYSQL_PASSWORD "$DB_IMAGE" >/dev/null ;;
  postgresql)
    POSTGRES_PASSWORD="$DB_PASSWORD" \
    docker run -d --name "$DB" --network "$NET" \
      -e POSTGRES_DB=vectispire -e POSTGRES_USER=vectispire \
      -e POSTGRES_PASSWORD "$DB_IMAGE" >/dev/null ;;
esac
wait_for_db
start_app "$APP_FROM" "$FROM_IMAGE"
FROM_VERSION=$(schema_version)
FROM_APPLIED=$(applied_count)
[ -n "$FROM_VERSION" ] || fail "$FROM_TAG is healthy and Flyway recorded no version — the drill is not looking at its database"
echo "  schema at V$FROM_VERSION, $FROM_APPLIED migrations applied"

log "2. real data, written through $FROM_TAG's API"
# The bootstrap account must change its password before any guarded route answers. Rotating
# revokes every session, the one that made the change included, so the sign-in is repeated.
TOKEN=$(login admin "$BOOTSTRAP_PASSWORD")
[ -n "$TOKEN" ] || fail "the bootstrap password was refused"
send POST "$TOKEN" /api/v1/auth/change-password \
  "{\"current_password\":\"$BOOTSTRAP_PASSWORD\",\"new_password\":\"$ROTATED_PASSWORD\"}" >/dev/null
TOKEN=$(login admin "$ROTATED_PASSWORD")
[ -n "$TOKEN" ] || fail "the rotated password was refused right after being set"
echo "  admin's password rotated"

send POST "$TOKEN" /api/v1/users \
  "{\"username\":\"analyst\",\"display_name\":\"Upgrade Analyst\",\"email\":\"analyst@example.org\",\"password\":\"$ANALYST_PASSWORD\",\"role\":\"security_champion\"}" >/dev/null
echo "  an analyst account"

SOLUTION_ID=$(send POST "$TOKEN" /api/v1/solutions \
  '{"name":"Upgrade drill","description":"Written by the previous release"}' | json id)
[ -n "$SOLUTION_ID" ] || fail "the solution has no id"
send POST "$TOKEN" "/api/v1/solutions/$SOLUTION_ID/projects" \
  '{"name":"Payments","description":"A project inside it"}' >/dev/null
echo "  a solution and a project"

REPO_ID=$(send POST "$TOKEN" /api/v1/repositories \
  '{"name":"upgrade-drill","url":"https://example.org/acme/upgrade-drill.git","branch":"main","scanManualOnly":true,"tier":"TIER_1_MISSION_CRITICAL"}' | json id)
[ -n "$REPO_ID" ] || fail "the repository has no id"
echo "  repository #$REPO_ID"

send PUT "$TOKEN" /api/v1/settings '{"retention_keep_per_target":"7","eol_warn_days":"45"}' >/dev/null
send PUT "$TOKEN" /api/v1/settings/webhook-secret '{"secret":"upgrade-drill-signing-secret"}' >/dev/null
echo "  two settings and the webhook signing secret"

API_KEY=$(send POST "$TOKEN" /api/v1/api-keys \
  '{"name":"upgrade-drill","scopes":["read"],"expires_in_days":30}' | json secret)
[ -n "$API_KEY" ] || fail "the API key was issued without its secret"
get "$API_KEY" /api/v1/repositories >/dev/null
echo "  an API key with the read scope, which authenticates"

AUDIT_BEFORE=$(get "$TOKEN" /api/v1/audit-log/verify)
[ -z "$(printf '%s' "$AUDIT_BEFORE" | json broken)" ] || fail "the audit chain is broken before the upgrade: $AUDIT_BEFORE"
AUDIT_TOTAL_BEFORE=$(printf '%s' "$AUDIT_BEFORE" | json total)
echo "  audit chain: $AUDIT_TOTAL_BEFORE entries, intact"

snapshot "$TOKEN" "$WORK/before.json"

log "3. $FROM_TAG stopped, as an operator stops it"
docker stop -t 30 "$APP_FROM" >/dev/null
docker rm "$APP_FROM" >/dev/null

log "4. this commit's control plane, on the same database"
start_app "$APP_TO" "$TO_IMAGE"
TO_VERSION=$(schema_version)
TO_APPLIED=$(applied_count)
FAILED=$(failed_count)
[ "$FAILED" = "0" ] || fail "$FAILED migration(s) recorded as failed in flyway_schema_history"
[ "$TO_APPLIED" -ge "$FROM_APPLIED" ] || fail "flyway_schema_history shrank from $FROM_APPLIED to $TO_APPLIED rows"
NEW=$(( TO_APPLIED - FROM_APPLIED ))
if [ "$NEW" -eq 0 ]; then
  echo "  schema still at V$TO_VERSION: no migration since $FROM_TAG — the drill proves the path and the data, not a migration"
else
  echo "  schema V$FROM_VERSION → V$TO_VERSION, $NEW migration(s) applied on rows:"
  sql "SELECT version, description FROM flyway_schema_history ORDER BY installed_rank DESC LIMIT $NEW" | sed 's/^/    V/'
fi
echo "  healthy with ddl-auto: validate — the entities agree with the migrated schema"

log "5. what $FROM_TAG wrote, read back by this commit"
# Read with the session $FROM_TAG issued, before anything else touches the database: a sign-in
# moves `activeSessions` and `lastLoginAt`, a use of the key its `lastUsedAt` — those are what the
# fields are for, and reading first is what lets the comparison hold every one of them.
get "$TOKEN" /api/v1/auth/me >/dev/null
echo "  the session $FROM_TAG issued is still valid"
snapshot "$TOKEN" "$WORK/after.json"

python3 - "$WORK/before.json" "$WORK/after.json" "$REWRITES" "$FROM_TAG" <<'PY'
import json, sys

before, after = (json.load(open(p)) for p in sys.argv[1:3])
rewrites_file, base = sys.argv[3], sys.argv[4]

# A migration that rewrites a value on purpose, accepted for the tag it is measured against.
# Same rule as the API's accepted breaks: a line for another tag, or one no difference used,
# fails — the list is empty again once the next tag carries the migration.
rewrites, problems = {}, []
with open(rewrites_file) as f:
    for n, line in enumerate(f, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [x.strip() for x in line.rstrip("\n").split(" | ")]
        if len(parts) != 4 or not all(parts):
            problems.append(f"{rewrites_file}:{n}: expected `tag | field path | migration | reason`"); continue
        if parts[0] != base:
            problems.append(f"{rewrites_file}:{n}: accepted against {parts[0]}, the release is now {base} — remove the line"); continue
        rewrites[parts[1]] = n
used = set()

# Fields that legitimately differ between two reads with nothing written in between, each with
# its reason. Kept short on purpose: every name here is a field the drill does not check.
VOLATILE = {
    "isExpired",    # computed against the clock at each read
}

# The lists also hold what the application seeds itself, which a new release may legitimately
# add to; only what the drill wrote is compared, found by the name it gave.
OWNED = {
    "repositories": ("name", {"upgrade-drill"}),
    "settings": ("key", {"retention_keep_per_target", "eol_warn_days"}),
    "api_keys": ("name", {"upgrade-drill"}),
    "users": ("username", {"admin", "analyst"}),
    "solutions": ("name", {"Upgrade drill"}),
}

def listed(doc):
    if isinstance(doc, list):
        return doc
    for v in doc.values():
        if isinstance(v, list):
            return v
    raise SystemExit(f"FAILED: no list in {str(doc)[:200]}")

compared = 0

def ident(x):
    if isinstance(x, dict):
        for k in ("id", "key", "username", "name"):
            if k in x:
                return x[k]
    return json.dumps(x, sort_keys=True)

# Every field the previous release returned must come back with the same value; a field the new
# release adds is not a difference (decision 0043 §1: the API is additive).
def compare(path, b, a):
    global compared
    if isinstance(b, dict):
        if not isinstance(a, dict):
            problems.append(f"{path}: was an object, now {a!r}"); return
        for k, bv in b.items():
            if k in VOLATILE:
                continue
            if k not in a:
                problems.append(f"{path}.{k}: was {bv!r}, absent after"); continue
            compare(f"{path}.{k}", bv, a[k])
    elif isinstance(b, list):
        if not isinstance(a, list):
            problems.append(f"{path}: was a list, now {a!r}"); return
        bi, ai = {ident(x): x for x in b}, {ident(x): x for x in a}
        for k, x in bi.items():
            if k not in ai:
                problems.append(f"{path}[{k}]: was there, absent after"); continue
            compare(f"{path}[{k}]", x, ai[k])
    else:
        compared += 1
        if b != a:
            if path in rewrites:
                used.add(path); print(f"  rewritten, as {rewrites_file}:{rewrites[path]} accepts: {path}: {b!r} → {a!r}")
            else:
                problems.append(f"{path}: {b!r} became {a!r}")

compare("webhook_secret", before["webhook_secret"], after["webhook_secret"])
if before["webhook_secret"].get("configured") is not True:
    problems.append("the webhook secret did not read as configured before the upgrade — nothing to compare")

for section, (field, names) in OWNED.items():
    b_items = [i for i in listed(before[section]) if i.get(field) in names]
    a_items = {i.get(field): i for i in listed(after[section]) if i.get(field) in names}
    if len(b_items) != len(names):
        problems.append(f"{section}: {len(b_items)} of the drill's {len(names)} object(s) in the first read — it would compare less than it wrote")
    for i in b_items:
        k = i[field]
        if k not in a_items:
            problems.append(f"{section}[{k}]: written by the previous release, absent after the upgrade"); continue
        compare(f"{section}[{k}]", i, a_items[k])
    print(f"  {section:<13} {len(b_items)} object(s) read back")

if compared == 0:
    problems.append("no field was compared")
for path, n in rewrites.items():
    if path not in used:
        problems.append(f"{rewrites_file}:{n}: accepts a rewrite of {path}, which did not happen — remove the line")
for p in problems:
    print(f"  MISMATCH {p}")
if problems:
    sys.exit("FAILED: the data written before the upgrade does not read back the same")
print(f"  {compared} field values identical")
PY

TOKEN=$(login admin "$ROTATED_PASSWORD")
[ -n "$TOKEN" ] || fail "the password rotated under $FROM_TAG is refused after the upgrade"
echo "  the password rotated under $FROM_TAG signs in"
[ -n "$(login analyst "$ANALYST_PASSWORD")" ] || fail "the analyst's password is refused after the upgrade"
echo "  so does the analyst's"
get "$API_KEY" /api/v1/repositories >/dev/null
echo "  the API key issued by $FROM_TAG authenticates"

AUDIT_AFTER=$(get "$TOKEN" /api/v1/audit-log/verify)
[ -z "$(printf '%s' "$AUDIT_AFTER" | json broken)" ] \
  || fail "the audit chain reports a break after the upgrade: $(printf '%s' "$AUDIT_AFTER" | json broken)"
AUDIT_TOTAL_AFTER=$(printf '%s' "$AUDIT_AFTER" | json total)
[ "$AUDIT_TOTAL_AFTER" -ge "$AUDIT_TOTAL_BEFORE" ] \
  || fail "the audit trail lost entries across the upgrade: $AUDIT_TOTAL_BEFORE before, $AUDIT_TOTAL_AFTER after"
echo "  audit chain: $AUDIT_TOTAL_AFTER entries, verified across the upgrade"

log "6. and this commit writes on the upgraded schema"
REPO2_ID=$(send POST "$TOKEN" /api/v1/repositories \
  '{"name":"upgrade-drill-after","url":"https://example.org/acme/upgrade-drill-after.git","branch":"main","scanManualOnly":true}' | json id)
[ -n "$REPO2_ID" ] || fail "the repository created after the upgrade has no id"
[ "$REPO2_ID" -gt "$REPO_ID" ] \
  || fail "the repository created after the upgrade got id $REPO2_ID, not after $REPO_ID — an id sequence went backwards"
echo "  repository #$REPO2_ID created after #$REPO_ID"

log "the upgrade drill passed on $ENGINE"
echo "  $FROM_TAG → this commit: V$FROM_VERSION → V$TO_VERSION, $NEW new migration(s), data read back as written"
