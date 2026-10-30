#!/usr/bin/env bash
#
# The signing-key rotation drill: a document signed before a rotation still verifies after it, the
# way a consumer checks it — with openssl, against the key the instance publishes by its id.
#
# **Why a drill and not only a test.** `SigningKeyServiceTest` builds the service twice on one
# database, which is what a restart does to the service. It cannot show that the image reads
# `VECTISPIRE_SIGNING_KEY`, that the routes are open to somebody with no account, or that the
# evidence bundle an auditor downloads is signed by the key the list says. This starts the image
# that ships, three times on one database, as `docs/en/KEY_ROTATION.md` tells an operator to:
#
#   1. no configured key: the instance generates one; an evidence bundle is downloaded;
#   2. a new key configured: another bundle; the first verifies against the retired key, the
#      second against the active one, and neither against the other's key;
#   3. the first key revoked: it is still listed, and `/crypto/verify` refuses its signature.
#
# It never touches a deployment: every container and network carries the `rotation-` prefix.
#
# Usage:
#   scripts/signing-key-rotation-drill.sh                  # needs vectispire:latest locally
#   VECTISPIRE_IMAGE=vectispire:nightly scripts/signing-key-rotation-drill.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${ROTATION_PREFIX-rotation}"
[ -n "$PREFIX" ] || { echo "refusing to run without a name prefix: it is the only thing keeping this off a deployment" >&2; exit 1; }

IMAGE="${VECTISPIRE_IMAGE:-vectispire:latest}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93}"
# The shipped composition's MySQL, read as the restore drill reads it.
MYSQL_IMAGE="$(sed -n 's/^[[:space:]]*image:[[:space:]]*\(mysql:[^[:space:]#]*\).*$/\1/p' "$ROOT/docker-compose.yml")"
printf '%s\n' "$MYSQL_IMAGE" | grep -Eqx 'mysql:[0-9][0-9.]*@sha256:[0-9a-f]{64}' \
  || { echo "docker-compose.yml's MySQL [$MYSQL_IMAGE] is not one mysql:<version>@sha256:<digest> line" >&2; exit 1; }

NET="${PREFIX}-net"
DB="${PREFIX}-db"
APP="${PREFIX}-app"

# Not secrets, and they must not look like ones: everything here is created and destroyed by the drill.
DRILL_KEY="cm90YXRpb24tZHJpbGwta2V5LW5vdC1hLXNlY3JldDA=" # gitleaks:allow — invented: "rotation-drill-key-not-a-secret0"
BOOTSTRAP_PASSWORD="AdminVectispire2026!"
ROTATED_PASSWORD="RotationDrill2026!"
WORK="$(mktemp -d)"

log()  { printf '\n\033[1m── %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local code=$?
  if [ "$code" != 0 ]; then
    echo "═══ $APP, last 80 lines"; docker logs --tail 80 "$APP" 2>&1 || true
  fi
  docker rm -f "$APP" "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Sessions and passwords on stdin as a curl config, never as arguments — the restore drill's helpers.
api() { docker run -i --rm --network "container:${APP}" "$CURL_IMAGE" -s -K - "$@"; }
cfg_quote() { local s="${1//\\/\\\\}"; printf '"%s"' "${s//\"/\\\"}"; }
bearer() { printf 'header = %s\n' "$(cfg_quote "Authorization: Bearer $1")"; }
body()   { printf 'data-raw = %s\n' "$(cfg_quote "$1")"; }
json()   { python3 -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else v)' "$1"; }

# Starts the control plane on the drill's database with the signing configuration given in the
# environment of this call: `VECTISPIRE_SIGNING_KEY` and `VECTISPIRE_SIGNING_REVOKED_KEYS`, empty or not.
start_app() {
  docker rm -f "$APP" >/dev/null 2>&1 || true
  VECTISPIRE_DB_PASSWORD=vectispire ENCRYPTION_KEY="$DRILL_KEY" VECTISPIRE_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" \
  docker run -d --name "$APP" --network "$NET" \
    -e VECTISPIRE_DB_URL="jdbc:mysql://${DB}:3306/vectispire" \
    -e VECTISPIRE_DB_USER=vectispire -e VECTISPIRE_DB_PASSWORD -e ENCRYPTION_KEY \
    -e VECTISPIRE_BOOTSTRAP_USERNAME=admin -e VECTISPIRE_BOOTSTRAP_PASSWORD \
    -e VECTISPIRE_EMBEDDED_WORKER=false \
    -e VECTISPIRE_SIGNING_KEY -e VECTISPIRE_SIGNING_REVOKED_KEYS \
    "$IMAGE" >/dev/null
  for attempt in $(seq 1 180); do
    api -f -o /dev/null "http://localhost:3180/actuator/health" </dev/null 2>/dev/null && { echo "  healthy after ${attempt}s"; return; }
    if [ "$(docker inspect -f '{{.State.Running}}' "$APP" 2>/dev/null)" != true ]; then return 1; fi
    sleep 1
  done
  fail "the control plane never became healthy"
}

login() {
  body "{\"username\":\"admin\",\"password\":\"$1\"}" \
    | api -X POST -H 'Content-Type: application/json' "http://localhost:3180/api/v1/auth/login" | json token
}

# The bootstrap account must change its password before a guarded route answers; the second start
# finds it changed already.
sign_in() {
  local token
  token="$(login "$ROTATED_PASSWORD")"
  if [ -z "$token" ]; then
    token="$(login "$BOOTSTRAP_PASSWORD")"
    [ -n "$token" ] || fail "neither password was accepted"
    { bearer "$token"; body "{\"current_password\":\"$BOOTSTRAP_PASSWORD\",\"new_password\":\"$ROTATED_PASSWORD\"}"; } \
      | api -X POST -H 'Content-Type: application/json' -o /dev/null -f "http://localhost:3180/api/v1/auth/change-password" \
      || fail "the password change was refused"
    token="$(login "$ROTATED_PASSWORD")"
  fi
  [ -n "$token" ] || fail "the drill could not sign in"
  printf '%s' "$token"
}

# Downloads an evidence bundle into $WORK/$1/ and unpacks its signed manifest.
bundle() {
  mkdir -p "$WORK/$1"
  bearer "$(sign_in)" | api -f "http://localhost:3180/api/v1/compliance/evidence-bundle.zip" > "$WORK/$1/bundle.zip" \
    || fail "the evidence bundle was refused"
  (cd "$WORK/$1" && python3 -c 'import zipfile,sys; zipfile.ZipFile("bundle.zip").extractall(".")')
  if [ ! -s "$WORK/$1/manifest.json" ] || [ ! -s "$WORK/$1/manifest.json.sig" ]; then
    fail "the bundle has no signed manifest: $(ls "$WORK/$1")"
  fi
}

# The key id of a PEM public key: the SHA-256 of its DER encoding, as the documents name it.
key_id() { openssl pkey -pubin -in "$1" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1; }

# What a consumer runs: the manifest's detached signature, checked with openssl alone.
verifies() {
  base64 -d < "$WORK/$1/manifest.json.sig" > "$WORK/$1/manifest.sig.der"
  openssl dgst -sha256 -verify "$2" -signature "$WORK/$1/manifest.sig.der" "$WORK/$1/manifest.json" >/dev/null 2>&1
}

published() { api -f "http://localhost:3180/api/v1/crypto/public-keys" </dev/null; }
fetch_key() { api -f "http://localhost:3180/api/v1/crypto/public-keys/$1.pub" </dev/null > "$2" || fail "key $1 is not published"; }
status_of() { python3 -c 'import json,sys; print(next((k["status"] for k in json.load(sys.stdin) if k["keyId"]==sys.argv[1]), "absent"))' "$1"; }

verify_route() {
  local payload sig
  payload="$(cat "$WORK/$1/manifest.json")"
  sig="$(tr -d '\n' < "$WORK/$1/manifest.json.sig")"
  { bearer "$(sign_in)"; body "$(python3 -c 'import json,sys; print(json.dumps({"payload": sys.argv[1], "signature": sys.argv[2]}))' "$payload" "$sig")"; } \
    | api -X POST -H 'Content-Type: application/json' -f "http://localhost:3180/api/v1/crypto/verify"
}

log "0. hygiene"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "$IMAGE not present — docker build -f Dockerfile -t $IMAGE ."
docker network create "$NET" >/dev/null
MYSQL_ROOT_PASSWORD=root MYSQL_PASSWORD=vectispire \
docker run -d --name "$DB" --network "$NET" \
  -e MYSQL_ROOT_PASSWORD -e MYSQL_DATABASE=vectispire -e MYSQL_USER=vectispire -e MYSQL_PASSWORD \
  "$MYSQL_IMAGE" >/dev/null
for attempt in $(seq 1 120); do
  docker exec "$DB" mysqladmin ping -h "$DB" --silent >/dev/null 2>&1 && break
  [ "$attempt" = 120 ] && fail "the database never became reachable"
  sleep 1
done

log "1. no key configured: the instance generates one and signs with it"
VECTISPIRE_SIGNING_KEY="" VECTISPIRE_SIGNING_REVOKED_KEYS="" start_app || fail "the first start failed" # gitleaks:allow — both empty: no key configured
bundle before
published > "$WORK/keys-1.json"
OLD_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["keyId"])' "$WORK/keys-1.json")"
[ "$(status_of "$OLD_ID" < "$WORK/keys-1.json")" = ACTIVE ] || fail "the generated key is not listed as active"
fetch_key "$OLD_ID" "$WORK/old.pub"
verifies before "$WORK/old.pub" || fail "the first bundle does not verify against the key published for it"
echo "  generated key $OLD_ID, bundle verified"

log "2. a new key configured: the old documents still verify, against the old key"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/new.pem" 2>/dev/null
openssl pkey -in "$WORK/new.pem" -pubout -out "$WORK/new-local.pub"
NEW_ID="$(key_id "$WORK/new-local.pub")"
VECTISPIRE_SIGNING_KEY="$(cat "$WORK/new.pem")" VECTISPIRE_SIGNING_REVOKED_KEYS="" start_app || fail "the start with a configured key failed"
bundle after
published > "$WORK/keys-2.json"
[ "$(status_of "$NEW_ID" < "$WORK/keys-2.json")" = ACTIVE ] || fail "the configured key is not active: $(cat "$WORK/keys-2.json")"
[ "$(status_of "$OLD_ID" < "$WORK/keys-2.json")" = RETIRED ] || fail "the replaced key is not listed as retired: $(cat "$WORK/keys-2.json")"
api -f "http://localhost:3180/api/v1/crypto/public-key.pub" </dev/null > "$WORK/active.pub"
[ "$(key_id "$WORK/active.pub")" = "$NEW_ID" ] || fail "public-key.pub does not serve the configured key"
fetch_key "$OLD_ID" "$WORK/old-again.pub"
verifies after "$WORK/active.pub" || fail "the new bundle does not verify against the active key"
verifies before "$WORK/old-again.pub" || fail "the bundle from before the rotation no longer verifies against its key"
! verifies before "$WORK/active.pub" || fail "the old bundle verifies against the new key — the check proves nothing"
! verifies after "$WORK/old-again.pub" || fail "the new bundle verifies against the old key — the check proves nothing"
reply="$(verify_route before)"
if [ "$(printf '%s' "$reply" | json valid)" != True ] || [ "$(printf '%s' "$reply" | json keyStatus)" != RETIRED ]; then
  fail "/crypto/verify does not accept the old bundle as a retired key's: $reply"
fi
echo "  $NEW_ID active, $OLD_ID retired; both bundles verify with openssl, each against its own key only"

log "3. the first key revoked: still listed, and nothing it signed is valid"
VECTISPIRE_SIGNING_KEY="$(cat "$WORK/new.pem")" VECTISPIRE_SIGNING_REVOKED_KEYS="$OLD_ID" start_app || fail "the start with a revocation failed"
[ "$(published | status_of "$OLD_ID")" = REVOKED ] || fail "the revoked key is not listed as revoked"
reply="$(verify_route before)"
if [ "$(printf '%s' "$reply" | json valid)" != False ] || [ "$(printf '%s' "$reply" | json keyStatus)" != REVOKED ]; then
  fail "/crypto/verify still accepts a revoked key's signature: $reply"
fi
reply="$(verify_route after)"
[ "$(printf '%s' "$reply" | json valid)" = True ] || fail "the active key's bundle stopped verifying: $reply"
echo "  $OLD_ID revoked: listed, and its signature refused"

log "4. a revoked key cannot be the one that signs"
if VECTISPIRE_SIGNING_KEY="$(cat "$WORK/new.pem")" VECTISPIRE_SIGNING_REVOKED_KEYS="$NEW_ID" start_app; then
  fail "the instance started signing with a revoked key"
fi
# Into a variable first: `docker logs | grep -q` under pipefail fails when grep stops reading early.
refusal="$(docker logs "$APP" 2>&1)"
grep -q "vectispire.signing.revoked-keys" <<<"$refusal" || fail "the refusal does not say why"
echo "  refused at start, with its reason"

log "the rotation drill passed"
