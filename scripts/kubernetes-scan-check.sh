#!/usr/bin/env bash
#
# **The chart's Kubernetes shape, asked to scan something** (decision 0045). A k3s cluster in a container,
# the chart installed as an operator installs it — the control plane behind its Ingress with TLS, the agent
# with `agents.executor: kubernetes`, the scans' namespace, its Role and its policies — the agent declared
# through the API and given its key, one repository registered, one scan run, and its steps read back.
#
# Why it exists: every piece of the Kubernetes executor is tested against a real cluster, and none of those
# tests starts the agent's image from the chart. What only this run sees is the composition: the variables
# the chart sets against the ones the agent reads, the Role the agent's calls need against the one rendered,
# the policies against the traffic a scan makes — the agent to the control plane through the Ingress, to the
# Git host, to the API server, and the scan pods to nothing — and the agent's start-up probe under them.
#
# **What is planted, and how it is judged, is `composition-scan-check.sh`'s**: its fixture repository (a
# token for the secrets scanner, a Terraform bucket for the IaC checker, an `eval` on input for the bundled
# SAST rule, a pinned requirement for the cataloguer and the matcher), served by `git daemon` from the same
# fixture image, and its matcher database in the pinned matcher's own schema, published in the agent's cache
# as `VulnerabilityDatabase` publishes a download. Every scanner must find what was planted for it; any
# failed step fails the check. Each scanner then ran as a pod in the scans' namespace, offline.
#
# Everything is local: the images are built here (`docker build`, native to this machine) and imported into
# the cluster; the scanner images are pulled by the cluster at the digests the product pins. Nothing is
# installed on this machine but the k3s container, removed at the end.
#
# Usage (from the repository root):
#   scripts/kubernetes-scan-check.sh                    # builds vectispire:k8s-check and vectispire-agent:k8s-check
#   CONTROL_PLANE_IMAGE=vectispire:x AGENT_IMAGE=vectispire-agent:x scripts/kubernetes-scan-check.sh
#   KEEP=1 scripts/kubernetes-scan-check.sh             # leave the cluster up to poke at
set -euo pipefail
[ -z "${TRACE:-}" ] || set -x

cd "$(dirname "$0")/.."
root="$PWD"
started_at=$SECONDS

NAME="${NAME:-vectispire-k8s-check}"
PORT="${PORT:-8443}"
CONTROL_PLANE_IMAGE="${CONTROL_PLANE_IMAGE:-}"
AGENT_IMAGE="${AGENT_IMAGE:-}"
# A Kubernetes its upstream still supports, as 0045 requires of a target; the one the executor's tests run.
K3S_IMAGE=rancher/k3s:v1.34.1-k3s1@sha256:5e0707cfd1239b358ef73f3254bc3eadc027dd30cd5ec6ca41e29e47652a1b8c
HELM_IMAGE=alpine/helm:3.22.0@sha256:70ed3f7b02ab2eee12aa520ad6870305db8a82516b07aff62f5656c657a26e2a
# The JDK's keytool, for the agent's truststore: the base the agent's own image is built on.
JDK_IMAGE="$(sed -n 's/^FROM \(eclipse-temurin[^ ]*\) AS build$/\1/p' "$root/Dockerfile.agent")"
MYSQL_IMAGE="$(sed -n 's/^ *image: \(mysql:[^ ]*\)$/\1/p' "$root/docker-compose.yml" | head -1)"
fixture_dir="$root/scripts/composition-scan-fixture"
GRYPE_IMAGE="$(grep -o 'anchore/grype@sha256:[0-9a-f]\{64\}' \
  "$root/vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerImages.java")"
BASE_IMAGE="$(sed -n 's/^FROM //p' "$fixture_dir/Dockerfile")"
# The control plane is reached at the name its Ingress answers to, which the agent resolves inside the
# cluster: the ingress controller's own Service. Kubernetes' DNS knows it; nothing has to be faked.
HOST=traefik.kube-system.svc.cluster.local
PACKAGE=vectispire-scan-check
ADVISORY=VSCHECK-2026-0001
SAST_RULE=vectispire.python.eval-on-input
AGENT_WORK=/var/lib/vectispire/agent-work

work="$(mktemp -d)"
fail() { echo "✗ $*" >&2; exit 1; }
elapsed() { echo "$(( SECONDS - $1 ))s"; }
AGENTS_NODE="$NAME-agents"
k() { docker exec -i "$NAME" kubectl "$@"; }
helm() {
  docker run --rm -i --network "container:$NAME" -v "$root/deploy/helm/vectispire:/chart:ro" -v "$work:/work:ro" \
    -e KUBECONFIG=/work/kubeconfig "$HELM_IMAGE" "$@"
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "── what the cluster had to say"
    k get pods -A -o wide 2>/dev/null || true
    k logs -n vectispire-agents deploy/vs-vectispire-agent --tail 80 2>/dev/null || true
    k logs -n vectispire deploy/vs-vectispire --tail 40 2>/dev/null || true
    k get events -n vectispire-scans --sort-by=.lastTimestamp 2>/dev/null | tail -20 || true
  fi
  if [ -z "${KEEP:-}" ]; then
    docker rm -f "$NAME" "$AGENTS_NODE" > /dev/null 2>&1 || true
    docker network rm "$NAME" > /dev/null 2>&1 || true
    rm -rf "$work"
  else
    echo "── kept: docker exec -it $NAME kubectl get pods -A ; work files in $work"
  fi
  exit "$status"
}
trap cleanup EXIT

# ── Images: the two Vectispire images built here unless named, and the fixture's.
if [ -z "$AGENT_IMAGE" ]; then
  echo "── building the agent's image"
  AGENT_IMAGE=vectispire-agent:k8s-check
  docker build -q -f "$root/Dockerfile.agent" -t "$AGENT_IMAGE" "$root" > /dev/null
fi
if [ -z "$CONTROL_PLANE_IMAGE" ]; then
  echo "── building the control plane's image"
  CONTROL_PLANE_IMAGE=vectispire:k8s-check
  docker build -q -f "$root/Dockerfile" -t "$CONTROL_PLANE_IMAGE" "$root" > /dev/null
fi

# ── The fixture repository: one commit, one thing for each scanner to find, baked into an image of the
# fixture's own base so the pod serving it needs no volume.
mkdir -p "$work/fixture/src" "$work/fixture/srv"
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
docker build -q -t vectispire-k8s-check-fixture-base:local "$fixture_dir" > /dev/null
printf 'FROM vectispire-k8s-check-fixture-base:local\nCOPY srv /srv\n' > "$work/fixture/Dockerfile"
docker build -q -t vectispire-k8s-check-fixture:local "$work/fixture" > /dev/null

# ── The matcher's database, the composition check's fixture, imported by the pinned matcher itself into
# the layout `VulnerabilityDatabase` publishes: a generation, `current` naming it, `checked` just now.
mkdir -p "$work/matcher" "$work/db"
python3 "$fixture_dir/matcher-db.py" "$work/matcher/vulnerability.db" "$PACKAGE" 2.0
chmod 644 "$work/matcher/vulnerability.db"
chmod 777 "$work/db"
generation="$(python3 -c 'import time; print(int(time.time() * 1000))')-$(openssl rand -hex 4)"
docker run --rm --network none -u 1000:1000 -v "$work/db:/db" -v "$work/matcher:/in:ro" \
  -e "GRYPE_DB_CACHE_DIR=/db/vectispire-vulnerability-db/generations/$generation" \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false "$GRYPE_IMAGE" db import /in/vulnerability.db > /dev/null
docker run --rm --network none -u 1000:1000 -v "$work/db:/db" --entrypoint sh "$BASE_IMAGE" -c '
  cd /db/vectispire-vulnerability-db && printf %s "$1" > current && date -u +%Y-%m-%dT%H:%M:%SZ > checked
  tar -C /db -cf /db/matcher.tar vectispire-vulnerability-db' sh "$generation"

# ── TLS for the Ingress, from an authority made for the run, and the agent's truststore holding it alone.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=vectispire-k8s-check-ca \
  -keyout "$work/ca.key" -out "$work/ca.crt" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$HOST" -keyout "$work/tls.key" -out "$work/tls.csr" 2> /dev/null
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$HOST" > "$work/tls.ext"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 2 \
  -extfile "$work/tls.ext" -out "$work/tls.crt" 2> /dev/null
truststore_password="$(openssl rand -hex 12)"
docker run --rm --network none -v "$work:/w" "$JDK_IMAGE" keytool -importcert -noprompt -alias check-ca \
  -file /w/ca.crt -keystore /w/truststore.p12 -storetype PKCS12 -storepass "$truststore_password" > /dev/null 2>&1
chmod 644 "$work"/*.crt "$work"/*.key "$work/truststore.p12"

# ── The cluster: two nodes, as the chart requires of an installation with agents. The control plane, the
# database and the ingress controller on the server; the agent and its scan pods on a node of their own,
# labelled and tainted, which nothing else tolerates. **One node is not enough, and should not be**: the
# control plane's required anti-affinity keeps scan pods off its node, so on a single node the agent's first
# probe pod stayed Pending and the agent, rightly, would not start (measured).
echo "── starting k3s, a server and an agents' node"
docker rm -f "$NAME" "$AGENTS_NODE" > /dev/null 2>&1 || true
docker network rm "$NAME" > /dev/null 2>&1 || true
docker network create "$NAME" > /dev/null
docker run -d --privileged --name "$NAME" --hostname "$NAME" --network "$NAME" -p "127.0.0.1:$PORT:443" "$K3S_IMAGE" \
  server --disable=metrics-server --tls-san=127.0.0.1 > /dev/null
deadline=$(( $(date +%s) + 300 ))
until docker exec "$NAME" test -s /var/lib/rancher/k3s/server/node-token 2> /dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the k3s server did not come up in 300s"
  sleep 2
done
docker run -d --privileged --name "$AGENTS_NODE" --hostname "$AGENTS_NODE" --network "$NAME" \
  -e "K3S_URL=https://$NAME:6443" -e "K3S_TOKEN=$(docker exec "$NAME" cat /var/lib/rancher/k3s/server/node-token)" \
  "$K3S_IMAGE" agent --node-label vectispire.dev/agents=true \
  --node-taint vectispire.dev/agents=true:NoSchedule > /dev/null
until [ "$(k get nodes --no-headers 2> /dev/null | grep -c ' Ready')" = 2 ] \
    && k get serviceaccount default -n default > /dev/null 2>&1 \
    && k get deployment traefik -n kube-system > /dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "k3s did not come up in 300s"
  sleep 3
done
docker exec "$NAME" cat /etc/rancher/k3s/k3s.yaml > "$work/kubeconfig"
chmod 644 "$work/kubeconfig"

echo "── importing the images"
digest_of() { # image reference as containerd names it, node container -> its manifest digest there
  docker exec "$2" ctr -n k8s.io images ls "name==$1" | awk 'NR == 2 { print $3 }'
}
qualified() { case "$1" in */*) printf 'docker.io/%s' "$1" ;; *) printf 'docker.io/library/%s' "$1" ;; esac; }
# Each where it runs: the control plane and the fixture on the server, the agent on the agents' node.
for image in "$CONTROL_PLANE_IMAGE" vectispire-k8s-check-fixture:local; do
  docker save "$image" | docker exec -i "$NAME" ctr -n k8s.io images import - > /dev/null
done
docker save "$AGENT_IMAGE" | docker exec -i "$AGENTS_NODE" ctr -n k8s.io images import - > /dev/null
cp_ref="$(qualified "$CONTROL_PLANE_IMAGE")"; agent_ref="$(qualified "$AGENT_IMAGE")"
cp_digest="$(digest_of "$cp_ref" "$NAME")"; agent_digest="$(digest_of "$agent_ref" "$AGENTS_NODE")"
if [ -z "$cp_digest" ] || [ -z "$agent_digest" ]; then fail "the imported images have no digest in the cluster"; fi
# **Named by digest as well as by tag.** The chart deploys `repository:tag@digest`, which the kubelet resolves
# as `repository@digest`: a registry serves that, and an imported image is known by its tag alone — so the
# kubelet went to Docker Hub for it and the control plane stayed in ImagePullBackOff (measured, k3s 1.34).
docker exec "$NAME" ctr -n k8s.io images tag "$cp_ref" "${cp_ref%:*}@$cp_digest" > /dev/null
docker exec "$AGENTS_NODE" ctr -n k8s.io images tag "$agent_ref" "${agent_ref%:*}@$agent_digest" > /dev/null

# The API server's real address — the endpoint of the `kubernetes` Service — which the agent calls and
# every scan pod is excluded from (agents.kubernetes.apiServer.cidrs).
api_endpoint="$(k get endpoints kubernetes -n default -o jsonpath='{.subsets[0].addresses[0].ip}')"

# ── The database: MySQL at the composition's digest, in the release's namespace.
echo "── the database"
db_password="$(openssl rand -hex 16)"
k create namespace vectispire > /dev/null
k create secret generic vectispire-database -n vectispire --from-literal=password="$db_password" > /dev/null
k create secret generic vectispire-keys -n vectispire \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --from-literal=bootstrap-password="Check-$(openssl rand -hex 12)!" > /dev/null
docker cp "$work/tls.crt" "$NAME:/tmp/tls.crt" && docker cp "$work/tls.key" "$NAME:/tmp/tls.key"
k create secret tls vectispire-tls -n vectispire --cert=/tmp/tls.crt --key=/tmp/tls.key > /dev/null
k apply -f - > /dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: mysql, namespace: vectispire}
spec:
  selector: {matchLabels: {app: mysql}}
  template:
    metadata: {labels: {app: mysql}}
    spec:
      containers:
      - name: mysql
        image: $MYSQL_IMAGE
        env:
        - {name: MYSQL_RANDOM_ROOT_PASSWORD, value: "yes"}
        - {name: MYSQL_DATABASE, value: vectispire}
        - {name: MYSQL_USER, value: vectispire}
        - {name: MYSQL_PASSWORD, valueFrom: {secretKeyRef: {name: vectispire-database, key: password}}}
        ports: [{containerPort: 3306}]
        readinessProbe: {exec: {command: [sh, -c, "mysqladmin ping -h 127.0.0.1 --silent"]}, periodSeconds: 3}
        resources: {requests: {memory: 512Mi, cpu: 100m}, limits: {memory: 1Gi}}
---
apiVersion: v1
kind: Service
metadata: {name: mysql, namespace: vectispire}
spec: {selector: {app: mysql}, ports: [{port: 3306}]}
EOF

# ── The fixture's Git host, in a namespace of its own: reached by the agent through an allowTo entry.
k create namespace scan-fixture > /dev/null
k apply -f - > /dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: fixture, namespace: scan-fixture}
spec:
  selector: {matchLabels: {app: fixture}}
  template:
    metadata: {labels: {app: fixture}}
    spec:
      containers:
      - name: git
        image: docker.io/library/vectispire-k8s-check-fixture:local
        imagePullPolicy: Never
        ports: [{containerPort: 9418}]
        resources: {requests: {memory: 32Mi, cpu: 20m}}
---
apiVersion: v1
kind: Service
metadata: {name: fixture, namespace: scan-fixture}
spec: {selector: {app: fixture}, ports: [{port: 9418}]}
EOF
k rollout status deployment/mysql -n vectispire --timeout=300s > /dev/null || fail "MySQL did not start"

# ── The chart, as an operator installs it: TLS at the Ingress, policies on, the Kubernetes executor.
cat > "$work/values.yaml" <<EOF
image:
  repository: ${cp_ref%:*}
  tag: "${cp_ref##*:}"
  digest: "$cp_digest"
database:
  url: jdbc:mysql://mysql.vectispire.svc.cluster.local:3306/vectispire
  password: {secretName: vectispire-database}
secrets:
  encryptionKey: {secretName: vectispire-keys}
  bootstrapPassword: {secretName: vectispire-keys}
trustedProxies: 10.42.0.0/16
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
ingress:
  className: traefik
  host: $HOST
  tls: {secretName: vectispire-tls}
  annotations: {}
resources:
  requests: {cpu: 250m, memory: 768Mi}
  limits: {memory: 2Gi}
auditMirror: {enabled: false}
agents:
  enabled: true
  executor: kubernetes
  image:
    repository: ${agent_ref%:*}
    tag: "${agent_ref##*:}"
    digest: "$agent_digest"
  controlPlaneUrl: https://$HOST
  token: {secretName: vectispire-agent}
  signingKey: {secretName: vectispire-agent}
  trustStore: {secretName: vectispire-agent-trust}
  extraEnv:
    - {name: JAVA_TOOL_OPTIONS, value: "-Djavax.net.ssl.trustStorePassword=$truststore_password"}
  resources:
    requests: {cpu: 100m, memory: 384Mi}
    limits: {memory: 1Gi}
  nodeSelector: {vectispire.dev/agents: "true"}
  tolerations:
    - {key: vectispire.dev/agents, operator: Exists, effect: NoSchedule}
  kubernetes:
    scanCpuMillis: 500
    scanMemoryMiB: 1536
    apiServer:
      cidrs: [$api_endpoint/32]
      ports: [6443]
  networkPolicy:
    # The pod and Service ranges of k3s, and the Docker network the node lives on.
    excludeCidrs: [10.42.0.0/16, 10.43.0.0/16, 172.16.0.0/12]
    allowTo:
      - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
        podSelector: {matchLabels: {app.kubernetes.io/name: traefik}}
        ports: [{port: 8443}]
      - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: scan-fixture}}
        ports: [{port: 9418}]
EOF
chmod 644 "$work/values.yaml"
echo "── installing the chart"
helm install vs /chart -n vectispire -f /work/values.yaml > /dev/null
k rollout status deployment/vs-vectispire -n vectispire --timeout=600s > /dev/null || fail "the control plane did not start"

base="https://$HOST:$PORT"
curl_() { curl -s --cacert "$work/ca.crt" --resolve "$HOST:$PORT:127.0.0.1" "$@"; }
deadline=$(( $(date +%s) + 300 ))
until curl_ -f "$base/actuator/health" > /dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the control plane did not answer through its Ingress in 300s"
  sleep 3
done
echo "── the control plane answers through its Ingress, in $(elapsed "$started_at")"

# Sessions, keys and passwords reach curl on stdin, never as arguments — the composition check's rule.
cfg_quote() { local s="${1//\\/\\\\}"; printf '"%s"' "${s//\"/\\\"}"; }
bearer() { printf 'header = %s\n' "$(cfg_quote "Authorization: Bearer $1")"; }
body()   { printf 'data-raw = %s\n' "$(cfg_quote "$1")"; }
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
login() {
  body "{\"username\":\"admin\",\"password\":\"$1\"}" \
    | curl_ -f -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/auth/login" | json 'd["token"]'
}
password="$(k get secret vectispire-keys -n vectispire -o jsonpath='{.data.bootstrap-password}' | base64 -d)"
rotated="Rotated-$(openssl rand -hex 12)!"
first="$(login "$password")"
{ bearer "$first"; body "{\"current_password\":\"$password\",\"new_password\":\"$rotated\"}"; } \
  | curl_ -f -K - -o /dev/null -X POST -H 'Content-Type: application/json' "$base/api/v1/auth/change-password"
session="$(login "$rotated")"
sast="$({ bearer "$session"; body '{"sast_enabled":"true"}'; } \
  | curl_ -K - -X PUT -H 'Content-Type: application/json' "$base/api/v1/settings")"
[ "$(printf '%s' "$sast" | json 'd["updated"]' 2>/dev/null)" = 1 ] || fail "SAST could not be switched on: $sast"

echo "── declaring the agent and handing it its key"
declared="$({ bearer "$session"; body '{"name":"k8s-check","credentials_mode":"delegated"}'; } \
  | curl_ -f -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/admin/agents")"
agent_id="$(printf '%s' "$declared" | json 'd["id"]')"
signing="$({ bearer "$session"; body '{"public_key":"generate"}'; } \
  | curl_ -f -K - -X PUT -H 'Content-Type: application/json' "$base/api/v1/admin/agents/$agent_id/signing-key" \
  | json 'd["privateKey"]')"
printf '%s' "$declared" | json 'd["secret"]' | tr -d '\n' > "$work/agent-token"
printf '%s' "$signing" > "$work/agent-signing-key"
docker cp "$work/agent-token" "$NAME:/tmp/agent-token" && docker cp "$work/agent-signing-key" "$NAME:/tmp/agent-signing-key"
docker cp "$work/truststore.p12" "$NAME:/tmp/truststore.p12"
k create secret generic vectispire-agent -n vectispire-agents \
  --from-file=token=/tmp/agent-token --from-file=signing-key=/tmp/agent-signing-key > /dev/null
k create secret generic vectispire-agent-trust -n vectispire-agents --from-file=truststore.p12=/tmp/truststore.p12 > /dev/null
docker exec "$NAME" rm -f /tmp/agent-token /tmp/agent-signing-key /tmp/tls.key

# The agent starts once its secrets exist; its start-up probe must pass under the chart's policies.
k rollout status deployment/vs-vectispire-agent -n vectispire-agents --timeout=600s > /dev/null \
  || fail "the agent did not start"
deadline=$(( $(date +%s) + 300 ))
until [[ "$(k logs -n vectispire-agents deploy/vs-vectispire-agent 2>/dev/null)" == *"the policies are enforced"* ]]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the agent never proved its scan pods are cut off"
  sleep 3
done
echo "✓ the agent started, and proved its scan pods cut off from the API server"

agent_pod="$(k get pods -n vectispire-agents -l app.kubernetes.io/component=agent -o jsonpath='{.items[0].metadata.name}')"
docker cp "$work/db/matcher.tar" "$NAME:/tmp/matcher.tar"
docker exec "$NAME" sh -c "kubectl exec -i -n vectispire-agents $agent_pod -c agent -- tar -x -C $AGENT_WORK < /tmp/matcher.tar"

echo "── one repository, one scan"
repository="$({ bearer "$session"; body '{"url":"git://fixture.scan-fixture.svc.cluster.local/fixture.git","branch":"main","name":"k8s-check"}'; } \
  | curl_ -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/repositories")"
repo_id="$(printf '%s' "$repository" | json 'd["id"]' 2>/dev/null)" || fail "the fixture repository was refused: $repository"
response="$(bearer "$session" | curl_ -K - -w '\n%{http_code}' -X POST "$base/api/v1/repositories/$repo_id/scan")"
code="${response##*$'\n'}"; answer="${response%$'\n'*}"
if [ "$code" = 200 ]; then
  scan_id="$(printf '%s' "$answer" | json 'd["id"]')"
else
  # Queued by the schedule before this asked: the composition check's reading, the same scan either way.
  scan_id="$(bearer "$session" | curl_ -f -K - "$base/api/v1/scans?repo_id=$repo_id" \
    | json 'max((s["id"] for s in d if s["status"] in ("pending", "scanning")), default="")')"
  [ -n "$scan_id" ] || fail "the scan was refused ($code): $answer"
fi
began=$SECONDS
deadline=$(( $(date +%s) + 1800 ))
while :; do
  detail="$(bearer "$session" | curl_ -f -K - "$base/api/v1/scans/$scan_id")"
  status="$(printf '%s' "$detail" | json 'd["scan"]["status"]')"
  case "$status" in pending | scanning) ;; *) break ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "scan $scan_id still $status after 1800s"
  sleep 5
done
printf '%s' "$detail" | python3 -c '
import collections, json, sys
d = json.load(sys.stdin); s = d["scan"]
kinds = collections.Counter(f["type"] for f in d["findings"])
print("status:", s["status"], "| findings:", d["findingsTotal"], dict(kinds), "| SBOM:", d["hasSbom"])
print("steps that failed:", s["error"] or "none")'
echo "   in $(elapsed "$began")"

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
    problems.append("no " + os.environ["SAST_RULE"] + " finding: the SAST engine did not read the tree")
if not found("vulnerability", os.environ["ADVISORY"]):
    problems.append("no " + os.environ["ADVISORY"] + " on " + os.environ["PACKAGE"] + ": the matcher did not read the SBOM")
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)' \
  || fail "the scan did not read the tree with every scanner"

# **The scan ran as pods, one per scanner**, scheduled in the scans' namespace — and the two probe pods
# before them — and none outlived it. Read from the cluster's events, since the agents list does not
# publish an agent's engine.
scheduled="$(k get events -n vectispire-scans --field-selector reason=Scheduled \
  -o jsonpath='{range .items[*]}{.involvedObject.name}{"\n"}{end}')"
for pod in vs-network-probe vs-gitleaks-secret-detection vs-syft-directory-sbom vs-grype-sbom-analysis \
    vs-checkov-iac-analysis vs-semgrep-source-code-analysis; do
  grep -q "^$pod-[0-9a-f]\{10\}$" <<< "$scheduled" || fail "no $pod pod was scheduled in the scans' namespace"
done
left="$(k get pods -n vectispire-scans -l vectispire.dev/agent --no-headers 2>/dev/null | wc -l | tr -d ' ')"
[ "$left" = 0 ] || fail "$left scan pod(s) outlived the scan"

echo "✓ the chart's Kubernetes shape scans: every scanner ran as a pod, read the tree and found its plant ($(elapsed "$started_at"))"
