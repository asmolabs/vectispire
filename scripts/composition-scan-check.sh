#!/usr/bin/env bash
#
# **The shipped composition, asked to scan something.** `docker-compose.yml` as it is, started with
# a throwaway `.env`, one repository registered, one scan run, and its steps read back.
#
# Why it exists: no job ever ran a scan through the composition. CI's `images` job and the nightly
# start the control plane with `VECTISPIRE_EMBEDDED_WORKER=false`, the browser suite runs the jar on
# the runner — and so, for as long as the composition existed, every scan it ran failed without any
# machine noticing. Three defects, one after the other, each hidden by the one before (2026-09-27):
#
#   1. The workspaces lived in the container's own `/tmp`, and the daemon resolves a bind's source on
#      its host: every scanner was handed an empty directory the daemon had just created ("no source
#      providers were able to resolve the input /repo/source").
#   2. With the workspace on a shared path, four scanners ran as a root with no capability, which
#      cannot read the 0700 workspace of an unprivileged control plane ("permission denied").
#   3. The socket proxy closes an idle connection after ten seconds and the client reused it: the
#      first image pull after a pause failed ("docker-proxy:2375 failed to respond").
#
# **Then an SSH clone with a managed key, because none had ever succeeded here** (2026-09-28). The
# image has no passwd entry for its user, so `user.home` was `/`: the known-hosts file could not be
# created ("The known-hosts file could not be prepared: /.ssh"), every keyed clone failed before
# connecting, and the scan said only "the clone failed". Behind it, the host-key policy called
# accept-new refused every first contact ("Server key did not validate"). So the repository is also
# served over SSH, from a throwaway `sshd` with a host key and a deployment key generated for the
# run; the key is registered through the API like an operator's, the scan must read the tree, the
# host's key must be written down, and once the fixture changes its host key the next scan must be
# refused as a changed host — never accepted.
#
# **Every scanner, for real, and each must find what was planted for it** (2026-09-28). The matcher,
# the IaC checker and the SAST engine used to be pointed at an image that does not exist, so only the
# cataloguer and the secrets scanner were proved to read the tree — and the second defect above was
# found for those three by hand, on a real repository. They now run at the digests the product pins,
# the way it runs them, and the scan must carry: a secret (a token generated for the run), an IaC
# finding (a Terraform bucket with none of its controls), the bundled SAST rule's finding
# (`vectispire.python.eval-on-input` on an `eval` of input — the rules the jar ships, so the step
# fetches nothing), an SBOM (a pinned requirement), and the matcher's match on that requirement.
# Any failed step fails the check: none is expected any more.
#
# **The matcher's database is a fixture, not the publisher's.** The real one is some 3 GB unpacked;
# what this is about is whether the matcher, started through the composition, runs as the workspace's
# owner, reads the SBOM and a database handed to it read-only and offline, and answers. So
# `composition-scan-fixture/matcher-db.py` writes a database in the pinned matcher's own schema with
# one advisory, `VSCHECK-2026-0001`, against a package nobody publishes; the pinned matcher imports it
# itself (`db import`, which writes the digest it later checks), and it is published in the executor's
# cache as `VulnerabilityDatabase` publishes a download — a generation, the `current` pointer, and the
# time of the last freshness check, so nothing is asked of the network. The match then takes the
# product's own path: `mountable()` resolves that generation, and the matcher mounts it read-only,
# without network, as the workspace's owner. A match on that advisory can only come from that file; a
# matcher running as root, unable to read the 0700 workspace, or finding no database fails the step.
# What is not run is the download itself (`db update`), which needs the publisher and the 3 GB.
#
# The fixture is a local repository served by `git daemon` from a container on the composition's own
# network, with a token generated for the run, and by `sshd` from another — nothing is cloned from the
# internet, nothing looks like a secret in this file. Both run an image built here from
# `composition-scan-fixture/Dockerfile`, on a base pinned by digest and with its packages installed at
# build time: nothing is installed when a fixture starts.
#
# **On Docker Desktop the scans' directories live in its VM**, because its file sharing answers a
# read of a shared host path whatever the owner and the mode: a scanner running as a root with no
# capability reads a 0700 directory of another user there, and the check would pass on exactly the
# defect it exists for — measured on 2026-09-28. Inside the VM the daemon is a Linux one and a mode is
# a mode. On a Linux host they stay under this run's temporary directory. Either way the script
# reaches them only through containers, as the daemon's host sees them.
#
# **Then the two failures a scan meets most, and the two fates the queue has for them** (2026-10-03).
# A repository the fixture's daemon does not serve must fail at its first attempt, saying it could not
# be found, with nothing scheduled — over `git://` it used to be retried three times, a quarter of an
# hour, before failing as "the clone failed". A host that does not resolve must wait and come back: the
# scan back in the queue after its first attempt, `notBefore` a minute after the failure. The minute is
# read off the scan's own sentence, which states the instant the queue computed, and checked against
# this machine's clock with a few seconds' slack — the daemon's host shares it, or is a VM kept in step
# with it. The attempts after the first are not waited for (five more minutes, then fifteen): the
# exact schedule is `CloneFailureFateTest`'s, on a clock moved by hand.
#
# **It never touches a deployment.** The composition runs under its own project name, and an override
# resets every fixed container, network and volume name so none of them is `vectispire-*`: a
# developer's running installation is left alone, and `down -v` removes only what this created.
#
# Usage (from the repository root):
#   scripts/composition-scan-check.sh                        # images vectispire:latest, vectispire-agent:latest
#   MODE=agent scripts/composition-scan-check.sh             # the scans run on the `with-agent` profile's agent
#   CONTROL_PLANE_IMAGE=vectispire:x AGENT_IMAGE=vectispire-agent:x scripts/composition-scan-check.sh
#   DAEMON_DIR=/somewhere scripts/composition-scan-check.sh  # the scans' directories, on the daemon's host
#   KEEP=1 scripts/composition-scan-check.sh                 # leave it up to poke at
set -euo pipefail
[ -z "${TRACE:-}" ] || set -x

cd "$(dirname "$0")/.."
root="$PWD"
started_at=$SECONDS

MODE="${MODE:-embedded}"
PROJECT="${PROJECT:-vectispire-scan-check}"
CONTROL_PLANE_IMAGE="${CONTROL_PLANE_IMAGE:-vectispire:latest}"
AGENT_IMAGE="${AGENT_IMAGE:-vectispire-agent:latest}"
# The fixture's servers: `git daemon`, since a repository URL is https, ssh or git — plain http is
# refused, and a certificate for a throwaway host would be more fixture than check — and `sshd`.
fixture_dir="$root/scripts/composition-scan-fixture"
FIXTURE_IMAGE="$PROJECT-fixture:local"
# Its base, for the containers that only need a shell: one digest, read where it is pinned.
BASE_IMAGE="$(sed -n 's/^FROM //p' "$fixture_dir/Dockerfile")"
# The matcher the product runs, read where the product pins it: the fixture database is imported by
# the very binary that will match against it.
GRYPE_IMAGE="$(grep -o 'anchore/grype@sha256:[0-9a-f]\{64\}' \
  "$root/vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerImages.java")"
PORT="${PORT:-3189}"
# The one the executors run as: `work-dir` hands the directory to it, and the images run as it.
EXECUTOR_USER=1000:1000
# What the fixture plants for each scanner.
PACKAGE=vectispire-scan-check
ADVISORY=VSCHECK-2026-0001
SAST_RULE=vectispire.python.eval-on-input

case "$MODE" in
  embedded | agent) ;;
  *) echo "MODE is embedded or agent, not \"$MODE\"" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
if [ -n "${DAEMON_DIR:-}" ]; then
  daemon_dir="$DAEMON_DIR"
elif [ "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" = "Docker Desktop" ]; then
  # Not shared with the Mac, so resolved in the VM: created there by the daemon, empty.
  daemon_dir="/var/lib/$PROJECT/$(basename "$work")"
else
  daemon_dir="$work"
fi
compose=(docker compose --project-directory "$root" -p "$PROJECT" -f "$root/docker-compose.yml"
         -f "$work/override.yml" --env-file "$work/.env" --profile with-agent)

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "── what the containers had to say"
    "${compose[@]}" logs --no-color --tail 80 control-plane agent 2>/dev/null || true
  fi
  if [ -z "${KEEP:-}" ]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    # The scans' directories are binds of the daemon's host, created by the daemon: removed the same
    # way, through a container, since the files in them are the executors' user's.
    docker run --rm --network none -u 0:0 --entrypoint rm -v "$daemon_dir:/w" "$BASE_IMAGE" \
      -rf /w/scans /w/agent-scans >/dev/null 2>&1 || true
    if [ "$daemon_dir" != "$work" ] && [ -z "${DAEMON_DIR:-}" ]; then
      docker run --rm --network none -u 0:0 --entrypoint rmdir -v "$(dirname "$daemon_dir"):/w" "$BASE_IMAGE" \
        "/w/$(basename "$daemon_dir")" >/dev/null 2>&1 || true
    fi
    docker image rm "$FIXTURE_IMAGE" >/dev/null 2>&1 || true
    rm -rf "$work"
  else
    echo "kept: project $PROJECT, files in $work, scans in $daemon_dir"
  fi
  exit "$status"
}
trap cleanup EXIT

fail() { echo "✗ $*" >&2; exit 1; }
elapsed() { echo "$(( SECONDS - $1 ))s"; }

# ── The throwaway secrets, generated here and never written anywhere else. No scanner image is
# named: blank keeps the digests `ScannerImages` pins, which is what an installation runs.
umask 077
cat > "$work/.env" <<EOF
MYSQL_PASSWORD=$(openssl rand -hex 16)
MYSQL_ROOT_PASSWORD=$(openssl rand -hex 16)
ENCRYPTION_KEY=$(openssl rand -base64 32)
VECTISPIRE_BOOTSTRAP_PASSWORD=Check-$(openssl rand -hex 12)!
VECTISPIRE_SIGNING_KEY=
VECTISPIRE_OIDC_CLIENT_SECRET=
VECTISPIRE_PORT=$PORT
VECTISPIRE_WORK_DIR=$daemon_dir/scans
VECTISPIRE_AGENT_WORK_DIR=$daemon_dir/agent-scans
VECTISPIRE_EMBEDDED_WORKER=$([ "$MODE" = embedded ] && echo true || echo false)
VECTISPIRE_HOST_SSH=false
EOF
umask 022
password="$(grep '^VECTISPIRE_BOOTSTRAP_PASSWORD=' "$work/.env" | cut -d= -f2-)"

echo "── building the fixture's image, and the matcher's database"
docker build -q -t "$FIXTURE_IMAGE" "$fixture_dir" >/dev/null
mkdir -p "$work/matcher"
python3 "$fixture_dir/matcher-db.py" "$work/matcher/vulnerability.db" "$PACKAGE" 2.0
chmod 644 "$work/matcher/vulnerability.db"

# ── The SSH fixture's keys: two host keys — the one it starts with and the one it changes to — and
# the deployment key the repository is registered with. Readable by the fixture's root, which copies
# them into place; the directory is this run's and removed with it.
mkdir -p "$work/ssh"
ssh-keygen -q -t ed25519 -N '' -C scan-check-host-a -f "$work/ssh/host_a"
ssh-keygen -q -t ed25519 -N '' -C scan-check-host-b -f "$work/ssh/host_b"
ssh-keygen -q -t ed25519 -N '' -C scan-check-deploy -f "$work/ssh/deploy"
cp "$work/ssh/deploy.pub" "$work/ssh/authorized_keys"
chmod 644 "$work/ssh/"*

# ── The fixture: one commit, one thing for each scanner to find, served by `git daemon`.
mkdir -p "$work/fixture/src" "$work/fixture/srv"
# Not `tr < /dev/urandom | head`: `head` closing the pipe is a SIGPIPE, and `pipefail` makes it fatal.
token="ghp_$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-36)"
printf 'GITHUB_TOKEN=%s\n' "$token" > "$work/fixture/src/deploy.env"
printf 'resource "aws_s3_bucket" "b" {\n  bucket = "scan-check"\n}\n' > "$work/fixture/src/main.tf"
printf '%s==1.0.0\n' "$PACKAGE" > "$work/fixture/src/requirements.txt"
printf 'import sys\n\nprint(eval(sys.argv[1]))\n' > "$work/fixture/src/app.py"
git -C "$work/fixture/src" init -q -b main
git -C "$work/fixture/src" -c user.name=check -c user.email=check@example.invalid add .
git -C "$work/fixture/src" -c user.name=check -c user.email=check@example.invalid commit -q -m fixture
git clone -q --bare "$work/fixture/src" "$work/fixture/srv/fixture.git"
chmod -R a+rX "$work/fixture/srv"

# ── The override: local images, and no name that could be a real installation's.
cat > "$work/override.yml" <<EOF
services:
  db:
    container_name: !reset null
  docker-proxy:
    container_name: !reset null
  control-plane:
    image: $CONTROL_PLANE_IMAGE
    container_name: !reset null
  work-dir:
    image: $CONTROL_PLANE_IMAGE
  keycloak:
    container_name: !reset null
  agent:
    image: $AGENT_IMAGE
    container_name: !reset null
  agent-work-dir:
    image: $AGENT_IMAGE
  agent-docker-proxy:
    container_name: !reset null
  # The image's own command: \`git daemon\`, as its unprivileged user.
  fixture:
    image: $FIXTURE_IMAGE
    volumes:
      - $work/fixture/srv:/srv:ro
    networks:
      - vectispire-net
      - vectispire-agent
  # The same repository over SSH. HOST_KEY picks which of the two host keys it presents;
  # changing it recreates the container, which is the fixture's way of being another server.
  sshfixture:
    image: $FIXTURE_IMAGE
    user: "0:0"
    environment:
      HOST_KEY: \${FIXTURE_HOST_KEY:-a}
    entrypoint: ["sh", "-c"]
    command:
      - >-
        install -d -o git -m 700 /home/git/.ssh && install -o git -m 600 /keys/authorized_keys /home/git/.ssh/ &&
        install -m 600 /keys/host_\$\$HOST_KEY /etc/ssh/host_key &&
        exec /usr/sbin/sshd -D -e -o HostKey=/etc/ssh/host_key -o PasswordAuthentication=no
    volumes:
      - $work/ssh:/keys:ro
      - $work/fixture/srv:/srv:ro
    networks:
      - vectispire-net
      - vectispire-agent
volumes:
  vectispire_mysql_data:
    name: !reset null
  vectispire_audit:
    name: !reset null
networks:
  vectispire-net:
    name: !reset null
  vectispire-db:
    name: !reset null
  vectispire-agent:
    name: !reset null
  vectispire-docker:
    name: !reset null
  vectispire-agent-docker:
    name: !reset null
EOF

base="http://127.0.0.1:$PORT"
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

# Publishes the fixture database in an executor's cache, laid out as `VulnerabilityDatabase` lays out
# what it downloads: `generations/<millis>-<8 hex>`, named by `current`, and `checked` just now so
# that `mountable()` takes it as it is instead of asking the publisher whether it is stale. Written as
# the executor's user, like everything else in that directory: the matcher has to read it as that
# user, and a root-owned file there would be one the executor could never retire.
publish_matcher_database() { # executor directory, on the daemon's host
  local generation
  generation="$(python3 -c 'import time; print(int(time.time() * 1000))')-$(openssl rand -hex 4)"
  docker run --rm --network none -u "$EXECUTOR_USER" -v "$1:/work" -v "$work/matcher:/in:ro" \
    -e "GRYPE_DB_CACHE_DIR=/work/vectispire-vulnerability-db/generations/$generation" \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false "$GRYPE_IMAGE" db import /in/vulnerability.db >/dev/null
  docker run --rm --network none -u "$EXECUTOR_USER" -v "$1:/work" --entrypoint sh "$BASE_IMAGE" -c '
    cd /work/vectispire-vulnerability-db && printf %s "$1" > current && date -u +%Y-%m-%dT%H:%M:%SZ > checked' \
    sh "$generation"
}

echo "── starting the composition ($MODE)"
"${compose[@]}" up -d --no-build --pull missing db docker-proxy work-dir control-plane fixture sshfixture >/dev/null
deadline=$(( $(date +%s) + 300 ))
until curl -sf "$base/actuator/health" > /dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the control plane did not become healthy in 300s"
  sleep 3
done

login() {
  curl -sf -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$1\"}" "$base/api/v1/auth/login" | json 'd["token"]'
}
rotated="Rotated-$(openssl rand -hex 12)!"
first="$(login "$password")"
curl -sf -o /dev/null -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $first" \
  -d "{\"current_password\":\"$password\",\"new_password\":\"$rotated\"}" "$base/api/v1/auth/change-password"
bearer="Authorization: Bearer $(login "$rotated")"
# The SAST step is off on a fresh installation (`sast_enabled`), and the dispatcher leaves it off the
# task: without this the engine never starts, and no step fails to say so.
sast="$(curl -s -X PUT -H "$bearer" -H 'Content-Type: application/json' -d '{"sast_enabled":"true"}' "$base/api/v1/settings")"
[ "$(printf '%s' "$sast" | json 'd["updated"]' 2>/dev/null)" = 1 ] || fail "SAST could not be switched on: $sast"

if [ "$MODE" = agent ]; then
  echo "── declaring the agent and starting it"
  # `delegated`, with a signing key pinned before it starts: that is the only way a managed key
  # reaches an agent (sealed for its process, decision 0031), and the SSH scan below needs one. The
  # repository without a credential goes to it all the same.
  declared="$(curl -sf -X POST -H "$bearer" -H 'Content-Type: application/json' \
    -d '{"name":"scan-check","credentials_mode":"delegated"}' "$base/api/v1/admin/agents")"
  agent_id="$(printf '%s' "$declared" | json 'd["id"]')"
  signing="$(curl -sf -X PUT -H "$bearer" -H 'Content-Type: application/json' -d '{"public_key":"generate"}' \
    "$base/api/v1/admin/agents/$agent_id/signing-key" | json 'd["privateKey"]')"
  # From the environment rather than the `.env`: the process's own variables win over the file.
  VECTISPIRE_AGENT_TOKEN="$(printf '%s' "$declared" | json 'd["secret"]')" VECTISPIRE_AGENT_SIGNING_KEY="$signing" \
    "${compose[@]}" up -d --no-build --pull missing agent-docker-proxy agent-work-dir agent >/dev/null
fi

executor=control-plane; executor_dir="$daemon_dir/scans"
[ "$MODE" = agent ] && { executor=agent; executor_dir="$daemon_dir/agent-scans"; }
# After `work-dir` handed the directory over, before anything is queued.
publish_matcher_database "$executor_dir"
echo "── ready in $(elapsed "$started_at")"

register() { # body -> repository id
  local repository
  repository="$(curl -s -X POST -H "$bearer" -H 'Content-Type: application/json' -d "$1" "$base/api/v1/repositories")"
  printf '%s' "$repository" | json 'd["id"]' > /dev/null 2>&1 || fail "the fixture repository was refused: $repository"
  printf '%s' "$repository" | json 'd["id"]'
}

queue() { # repository id -> scan id
  local scan_id
  scan_id="$(curl -sf -X POST -H "$bearer" "$base/api/v1/repositories/$1/scan" | json 'd["id"]')"
  echo "── scan $scan_id queued" >&2
  printf '%s' "$scan_id"
}

# Queues a scan of repository $1, waits for it to finish, prints it, and leaves its detail in $detail.
scan() {
  local scan_id status deadline began=$SECONDS
  scan_id="$(queue "$1")"
  deadline=$(( $(date +%s) + 900 ))
  while :; do
    detail="$(curl -sf -H "$bearer" "$base/api/v1/scans/$scan_id")"
    status="$(printf '%s' "$detail" | json 'd["scan"]["status"]')"
    case "$status" in
      pending | scanning) ;;
      *) break ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || fail "scan $scan_id still $status after 900s"
    sleep 5
  done
  printf '%s' "$detail" | python3 -c '
import collections, json, sys
d = json.load(sys.stdin); s = d["scan"]
kinds = collections.Counter(f["type"] for f in d["findings"])
print("status:", s["status"], "| findings:", d["findingsTotal"], dict(kinds), "| SBOM:", d["hasSbom"])
print("steps that failed:", s["error"] or "none")'
  echo "   in $(elapsed "$began")"
}

# What the check is for: every scanner read the tree and reported what was planted for it. No step
# may fail. In agent mode the control plane's worker is off, so a completed scan is the agent's: a
# finished scan names no claimant any more, and needs none here.
scanned_the_tree() {
  printf '%s' "$detail" | ADVISORY="$ADVISORY" PACKAGE="$PACKAGE" SAST_RULE="$SAST_RULE" python3 -c '
import json, os, sys
d = json.load(sys.stdin); s = d["scan"]; findings = d["findings"]
def found(kind, identifier=None):
    return any(f["type"] == kind and (identifier is None or f["identifier"] == identifier) for f in findings)
problems = []
if s["status"] != "completed":
    problems.append("the scan is " + s["status"] + ", not completed")
for step in (s["error"] or "").split(" | "):
    if step:
        problems.append("a step failed: " + step)
if not d["hasSbom"]:
    problems.append("no SBOM: the cataloguer did not read the tree")
if not found("secret"):
    problems.append("no secret found: the secrets scanner did not read the tree")
if not found("iac"):
    problems.append("no IaC finding: the IaC checker did not read the tree")
if not found("sast", os.environ["SAST_RULE"]):
    problems.append("no " + os.environ["SAST_RULE"] + " finding: the SAST engine did not read the tree with the bundled rules")
if not found("vulnerability", os.environ["ADVISORY"]):
    problems.append("no " + os.environ["ADVISORY"] + " on " + os.environ["PACKAGE"]
                    + ": the matcher did not read the SBOM against the database published for it")
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)'
}

# Assigned before use: a registration refused inside `scan "$(…)"` would not stop the script.
plain_repo="$(register '{"url":"git://fixture/fixture.git","branch":"main","name":"scan-check"}')"
scan "$plain_repo"
scanned_the_tree
echo "✓ the composition scans: the tree reached every scanner, and each read it"

# ── Over SSH, with a managed key.
echo "── the same repository over SSH, with a deployment key registered through the API"
key_id="$(python3 -c 'import json, sys; print(json.dumps({"name": "scan-check", "private_key": open(sys.argv[1]).read(),
    "public_key": open(sys.argv[2]).read().strip()}))' "$work/ssh/deploy" "$work/ssh/deploy.pub" \
  | curl -sf -X POST -H "$bearer" -H 'Content-Type: application/json' --data-binary @- "$base/api/v1/ssh-keys" | json 'd["id"]')"
ssh_repo="$(register "{\"url\":\"ssh://git@sshfixture/srv/fixture.git\",\"branch\":\"main\",\"name\":\"scan-check-ssh\",\"sshKeyId\":\"$key_id\"}")"
scan "$ssh_repo"
scanned_the_tree
# Read through a container: the directory is 0700 and the executor's user's, not this script's.
recorded="$(docker run --rm --network none -u "$EXECUTOR_USER" --entrypoint cat -v "$executor_dir:/w:ro" "$BASE_IMAGE" \
  /w/home/.ssh/known_hosts 2>&1 || true)"
printf '%s\n' "$recorded" | grep -qF "$(cut -d' ' -f2 "$work/ssh/host_a.pub")" \
  || fail "the fixture's host key was not written to the executor's known_hosts: $recorded"
# Captured, then searched: `logs | grep -q` stops reading at the first match, `logs` dies of SIGPIPE,
# and under `pipefail` the pipeline reads as "not found" — a check that passes by breaking.
logs="$("${compose[@]}" logs --no-color "$executor" 2>/dev/null)"
case "$logs" in
  *"Creating directories for"*) fail "the executor has no writable home: JGit could not create its configuration directory" ;;
esac
echo "✓ an SSH clone with a managed key reads the tree, and the host's key is written down"

echo "── the fixture changes its host key: the next scan must be refused, not accepted"
FIXTURE_HOST_KEY=b "${compose[@]}" up -d --no-build sshfixture >/dev/null
deadline=$(( $(date +%s) + 120 ))
until [[ "$("${compose[@]}" logs sshfixture 2>/dev/null)" == *"Server listening"* ]]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the SSH fixture did not come back with its new host key"
  sleep 2
done
changed="has changed since the last clone"
# Read off the scan in both modes. An agent hands no result back for a scan it could not run — an
# empty one would resolve the backlog — and it used to hand back nothing at all: the scan waited for
# its lease to lapse, and the refusal was in the agent's log alone. It reports the failure now, so
# the scan fails with the reason, each attempt in one poll — a lapse would take twenty minutes each.
started=$(date +%s)
scan "$ssh_repo"
printf '%s' "$detail" | CHANGED="$changed" MODE="$MODE" python3 -c '
import json, os, sys
s = json.load(sys.stdin)["scan"]; error = s["error"] or ""
problems = []
if s["status"] != "failed" or os.environ["CHANGED"] not in error:
    problems.append("a changed host key was not refused as one: " + s["status"] + " — " + error)
if os.environ["MODE"] == "agent" and "could not run on agent" not in error:
    problems.append("the agent did not report the failure: " + error)
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)'
if [ "$MODE" = agent ] && [ $(( $(date +%s) - started )) -ge 600 ]; then
  fail "the agent's failure took $(( $(date +%s) - started ))s to reach the scan: it waited for a lease, not a report"
fi
echo "✓ a changed host key is refused, and said to be one"

# Waits for scan $1's first attempt to end, and leaves its detail in $detail. Not `scan`, which waits
# for the scan to finish: a failure read as transient would take its three attempts first, six minutes.
first_attempt() {
  local ended deadline=$(( $(date +%s) + 300 ))
  while :; do
    detail="$(curl -sf -H "$bearer" "$base/api/v1/scans/$1")"
    ended="$(printf '%s' "$detail" | json 'd["scan"]["attempts"] >= 1 and d["scan"]["status"] != "scanning"')"
    [ "$ended" = True ] && return
    [ "$(date +%s)" -lt "$deadline" ] || fail "scan $1 did not end its first attempt in 300s"
    sleep 2
  done
}

# ── A repository that is not there: failed at once, and why.
echo "── a repository the fixture does not serve: failed at its first attempt, nothing scheduled"
missing_repo="$(register '{"url":"git://fixture/missing.git","branch":"main","name":"scan-check-missing"}')"
missing_scan="$(queue "$missing_repo")"
first_attempt "$missing_scan"
printf '%s' "$detail" | python3 -c '
import json, sys
s = json.load(sys.stdin)["scan"]; error = s["error"] or ""
problems = []
if s["status"] != "failed":
    problems.append("the scan is " + s["status"] + ", not failed")
if s["attempts"] != 1:
    problems.append("it took " + str(s["attempts"]) + " attempts: a missing repository was retried")
if s["notBefore"] is not None:
    problems.append("a retry is scheduled for " + s["notBefore"])
if "another attempt would meet the same refusal" not in error or "git://fixture/missing.git could not be found." not in error:
    problems.append("the reason is not that the repository could not be found: " + error)
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)'
echo "✓ a missing repository fails at its first attempt, and says it could not be found"

# ── A host that cannot be reached: back in the queue, a minute later.
echo "── a host that does not resolve: back in the queue, not before a minute after the failure"
unreachable_repo="$(register '{"url":"git://unreachable.invalid/fixture.git","branch":"main","name":"scan-check-unreachable"}')"
queued_at=$(date +%s)
unreachable_scan="$(queue "$unreachable_repo")"
first_attempt "$unreachable_scan"
observed_at=$(date +%s)
printf '%s' "$detail" | QUEUED_AT="$queued_at" OBSERVED_AT="$observed_at" python3 -c '
import datetime, json, os, re, sys
s = json.load(sys.stdin)["scan"]; error = s["error"] or ""
problems = []
if s["status"] != "pending" or s["attempts"] != 1:
    problems.append("after its first attempt the scan is " + s["status"] + " at attempt " + str(s["attempts"])
                    + ", not pending at attempt 1: " + error)
if "could not reach its host" not in error:
    problems.append("the reason is not an unreachable host: " + error)
stated = re.search(r"not before (\S+): ", error)
if s["notBefore"] is None or stated is None:
    problems.append("no retry is scheduled: " + str(s["notBefore"]) + " — " + error)
else:
    def epoch(text):  # microseconds at most: what every Python 3 reads
        return datetime.datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00")).timestamp()
    not_before = epoch(s["notBefore"])
    # The failure happened between the queueing and the observation; a few seconds of slack for the
    # clocks, and for the sentence stating the instant to the second.
    low, high = int(os.environ["QUEUED_AT"]) + 60 - 5, int(os.environ["OBSERVED_AT"]) + 60 + 5
    if not low <= not_before <= high:
        problems.append("notBefore " + s["notBefore"] + " is not a minute after the failure")
    if abs(epoch(stated.group(1)) - not_before) >= 1:
        problems.append("the sentence says " + stated.group(1) + ", the scan " + s["notBefore"])
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)'
echo "✓ an unreachable host is retried, a minute after the failure"
echo "── done in $(elapsed "$started_at")"
