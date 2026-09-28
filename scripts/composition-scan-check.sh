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
# **Cheap by choice.** The cataloguer and the secrets scanner run for real — they read the tree, one
# of them read-only and one writing its report, which is what the first two defects broke. The
# matcher, the IaC checker and the SAST engine are pointed at an image that does not exist, so their
# steps are absent in seconds: the matcher's database alone is 3 GB, and what this check is about is
# whether a scanner container sees the workspace at all, not what each tool finds in it. The fixture
# is a local repository served by `git daemon` from a container on the composition's own network,
# with a token generated for the run, and by `sshd` from another — nothing is cloned from the
# internet, nothing looks like a secret in this file.
#
# **It never touches a deployment.** The composition runs under its own project name, and an override
# resets every fixed container, network and volume name so none of them is `vectispire-*`: a
# developer's running installation is left alone, and `down -v` removes only what this created.
#
# Usage (from the repository root):
#   scripts/composition-scan-check.sh                        # images vectispire:latest, vectispire-agent:latest
#   MODE=agent scripts/composition-scan-check.sh             # the scans run on the `with-agent` profile's agent
#   CONTROL_PLANE_IMAGE=vectispire:x AGENT_IMAGE=vectispire-agent:x scripts/composition-scan-check.sh
#   KEEP=1 scripts/composition-scan-check.sh                 # leave it up to poke at
set -euo pipefail
[ -z "${TRACE:-}" ] || set -x

cd "$(dirname "$0")/.."
root="$PWD"

MODE="${MODE:-embedded}"
PROJECT="${PROJECT:-vectispire-scan-check}"
CONTROL_PLANE_IMAGE="${CONTROL_PLANE_IMAGE:-vectispire:latest}"
AGENT_IMAGE="${AGENT_IMAGE:-vectispire-agent:latest}"
# The fixture's server: `git daemon`, since a repository URL is https, ssh or git — plain http is
# refused, and a certificate for a throwaway host would be more fixture than check. Alpine with its
# `git-daemon` package, installed when the fixture starts: the images that ship git leave it out.
FIXTURE_IMAGE="${FIXTURE_IMAGE:-alpine:3.22}"
PORT="${PORT:-3189}"
# An image nobody publishes: `.invalid` is reserved (RFC 2606), so the pull fails at once.
SKIPPED="vectispire-scan-check.invalid/skipped:0"

case "$MODE" in
  embedded | agent) ;;
  *) echo "MODE is embedded or agent, not \"$MODE\"" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
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
    # The scans' directory is a bind of the daemon's host, created by the daemon: removed the same
    # way, through a container, since the files in it are the control plane's user's.
    docker run --rm --entrypoint rm -v "$work:/w" "$FIXTURE_IMAGE" -rf /w/scans /w/agent-scans >/dev/null 2>&1 || true
    rm -rf "$work"
  else
    echo "kept: project $PROJECT, files in $work"
  fi
  exit "$status"
}
trap cleanup EXIT

fail() { echo "✗ $*" >&2; exit 1; }

# ── The throwaway secrets, generated here and never written anywhere else.
umask 077
cat > "$work/.env" <<EOF
MYSQL_PASSWORD=$(openssl rand -hex 16)
MYSQL_ROOT_PASSWORD=$(openssl rand -hex 16)
ENCRYPTION_KEY=$(openssl rand -base64 32)
VECTISPIRE_BOOTSTRAP_PASSWORD=Check-$(openssl rand -hex 12)!
VECTISPIRE_SIGNING_KEY=
VECTISPIRE_OIDC_CLIENT_SECRET=
VECTISPIRE_PORT=$PORT
VECTISPIRE_WORK_DIR=$work/scans
VECTISPIRE_AGENT_WORK_DIR=$work/agent-scans
VECTISPIRE_IMAGE_GRYPE=$SKIPPED
VECTISPIRE_IMAGE_CHECKOV=$SKIPPED
VECTISPIRE_IMAGE_SEMGREP=$SKIPPED
VECTISPIRE_EMBEDDED_WORKER=$([ "$MODE" = embedded ] && echo true || echo false)
VECTISPIRE_HOST_SSH=false
EOF
umask 022
password="$(grep '^VECTISPIRE_BOOTSTRAP_PASSWORD=' "$work/.env" | cut -d= -f2-)"

# ── The SSH fixture's keys: two host keys — the one it starts with and the one it changes to — and
# the deployment key the repository is registered with. Readable by the fixture's root, which copies
# them into place; the directory is this run's and removed with it.
mkdir -p "$work/ssh"
ssh-keygen -q -t ed25519 -N '' -C scan-check-host-a -f "$work/ssh/host_a"
ssh-keygen -q -t ed25519 -N '' -C scan-check-host-b -f "$work/ssh/host_b"
ssh-keygen -q -t ed25519 -N '' -C scan-check-deploy -f "$work/ssh/deploy"
cp "$work/ssh/deploy.pub" "$work/ssh/authorized_keys"
chmod 644 "$work/ssh/"*

# ── The fixture: one commit, one generated token, served by `git daemon`.
mkdir -p "$work/fixture/src" "$work/fixture/srv"
# Not `tr < /dev/urandom | head`: `head` closing the pipe is a SIGPIPE, and `pipefail` makes it fatal.
token="ghp_$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-36)"
printf 'GITHUB_TOKEN=%s\n' "$token" > "$work/fixture/src/deploy.env"
printf 'resource "aws_s3_bucket" "b" {\n  bucket = "scan-check"\n}\n' > "$work/fixture/src/main.tf"
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
  fixture:
    image: $FIXTURE_IMAGE
    # safe.directory: the repository belongs to whoever ran this script, not to the daemon's root.
    entrypoint: ["sh", "-c"]
    command:
      - apk add --no-cache -q git-daemon && exec git -c safe.directory='*' daemon --reuseaddr --export-all --base-path=/srv /srv
    volumes:
      - $work/fixture/srv:/srv:ro
    networks:
      - vectispire-net
      - vectispire-agent
  # The same repository over SSH. HOST_KEY picks which of the two host keys it presents;
  # changing it recreates the container, which is the fixture's way of being another server.
  sshfixture:
    image: $FIXTURE_IMAGE
    environment:
      HOST_KEY: \${FIXTURE_HOST_KEY:-a}
    entrypoint: ["sh", "-c"]
    command:
      - >-
        apk add --no-cache -q openssh-server git &&
        adduser -D -s /usr/bin/git-shell git && sed -i 's/^git:!/git:*/' /etc/shadow &&
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
  local scan_id status deadline
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
import json, sys
d = json.load(sys.stdin); s = d["scan"]
print("status:", s["status"], "| findings:", d["findingsTotal"], "| SBOM:", d["hasSbom"], "| by:", s["claimedBy"])
print("steps that failed:", s["error"] or "none")'
}

# What the check is for: the two scanners that ran for real read the tree. The skipped ones are
# expected in the error, and nothing else is. In agent mode the control plane's worker is off, so a
# completed scan is the agent's: a finished scan names no claimant any more, and needs none here.
scanned_the_tree() {
  printf '%s' "$detail" | SKIPPED="$SKIPPED" python3 -c '
import json, os, sys
d = json.load(sys.stdin); s = d["scan"]; error = s["error"] or ""
problems = []
if s["status"] != "completed":
    problems.append("the scan is " + s["status"] + ", not completed")
if not d["hasSbom"]:
    problems.append("no SBOM: the cataloguer did not read the tree")
if not any(f["type"] == "secret" for f in d["findings"]):
    problems.append("no secret found: the secrets scanner did not read the tree")
for step in error.split(" | "):
    # The matcher runs after the cataloguer, so its missing image is the dependencies step failing.
    if step and not (step.startswith("dependencies:") and os.environ["SKIPPED"] in step
                     or step.startswith("IaC:") or step.startswith("SAST:")):
        problems.append("unexpected failure: " + step)
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)'
}

# Assigned before use: a registration refused inside `scan "$(…)"` would not stop the script.
plain_repo="$(register '{"url":"git://fixture/fixture.git","branch":"main","name":"scan-check"}')"
scan "$plain_repo"
scanned_the_tree
echo "✓ the composition scans: the tree reached the scanners, and they read it"

# ── Over SSH, with a managed key.
echo "── the same repository over SSH, with a deployment key registered through the API"
key_id="$(python3 -c 'import json, sys; print(json.dumps({"name": "scan-check", "private_key": open(sys.argv[1]).read(),
    "public_key": open(sys.argv[2]).read().strip()}))' "$work/ssh/deploy" "$work/ssh/deploy.pub" \
  | curl -sf -X POST -H "$bearer" -H 'Content-Type: application/json' --data-binary @- "$base/api/v1/ssh-keys" | json 'd["id"]')"
ssh_repo="$(register "{\"url\":\"ssh://git@sshfixture/srv/fixture.git\",\"branch\":\"main\",\"name\":\"scan-check-ssh\",\"sshKeyId\":\"$key_id\"}")"
scan "$ssh_repo"
scanned_the_tree
executor=control-plane; executor_dir="$work/scans"
[ "$MODE" = agent ] && { executor=agent; executor_dir="$work/agent-scans"; }
# Read through a container: the directory is 0700 and the executor's user's, not this script's.
recorded="$(docker run --rm --entrypoint cat -v "$executor_dir:/w:ro" "$FIXTURE_IMAGE" /w/home/.ssh/known_hosts 2>&1 || true)"
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
if [ "$MODE" = embedded ]; then
  scan "$ssh_repo"
  printf '%s' "$detail" | CHANGED="$changed" python3 -c '
import json, os, sys
s = json.load(sys.stdin)["scan"]
if s["status"] != "failed" or os.environ["CHANGED"] not in (s["error"] or ""):
    print("✗ a changed host key was not refused as one: " + s["status"] + " — " + str(s["error"]), file=sys.stderr); sys.exit(1)'
else
  # An agent hands nothing back for a scan it could not run — an empty result would resolve the
  # backlog — so the scan waits for its lease to lapse and the refusal is in the agent's log alone.
  scan_id="$(queue "$ssh_repo")"
  deadline=$(( $(date +%s) + 300 ))
  until said="$("${compose[@]}" logs --no-color agent 2>/dev/null | grep "Scan $scan_id abandoned:")"; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "the agent neither refused nor ran scan $scan_id in 300s"
    sleep 3
  done
  echo "$said"
  case "$said" in
    *"$changed"*) ;;
    *) fail "a changed host key was not refused as one" ;;
  esac
  status="$(curl -sf -H "$bearer" "$base/api/v1/scans/$scan_id" | json 'd["scan"]["status"]')"
  [ "$status" != completed ] || fail "scan $scan_id completed against a changed host key"
fi
echo "✓ a changed host key is refused, and said to be one"
