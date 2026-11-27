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
# **Then over SSH, with the forge's host key pinned** (`agents.knownHosts`): the same tree served by `sshd` from the
# fixture's image, cloned with a deployment key — and once more by another name of the same server, which the pin
# does not list and which must be refused, not learnt: a pin the agent could write would be a list it records new
# hosts into. The chart mounts the pin where the agent reads it, with no init container, since the Rust agent's
# image has no `sh` to run one in.
#
# **Then an image target** (decision 0045 §8): Alpine 3.20.3 by its index digest, from Docker Hub — so this check needs
# the internet, as the scanner images' pulls already do — copied by crane in a pod of its own under the online policy,
# and its inventory required to be the image's fourteen packages for x86_64.
#
# **Either agent's image**, installed the same way: the Java agent's by default, the Rust agent's with `AGENT=rust`
# (built from `vectispire-rust/Dockerfile.agent`) or any image named by `AGENT_IMAGE`. Nothing below asks which one
# runs — its trust store Secret carries the PKCS12 store and its PEM form, and the matcher's database is put in its
# work directory from a container of the check's own, since the Rust image has no `tar` to receive it.
#
# Usage (from the repository root):
#   scripts/kubernetes-scan-check.sh                    # builds vectispire:k8s-check and vectispire-agent:k8s-check
#   AGENT=rust scripts/kubernetes-scan-check.sh         # the Rust agent's image instead, vectispire-agent-rs:k8s-check
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
AGENT="${AGENT:-java}"
case "$AGENT" in java | rust) ;; *) echo "AGENT is java or rust, not \"$AGENT\"" >&2; exit 2 ;; esac
# A Kubernetes its upstream still supports, as 0045 requires of a target; the one the executor's tests run.
K3S_IMAGE=rancher/k3s:v1.34.12-k3s1@sha256:4ea0adb6b0ffedab0c58ffe5c99a49f2f7be871f38636c8baa2692899648d8c5
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
    # The nodes first, and the agents' node's own k3s log: on 2026-10-27 a nightly stopped at "k3s did not come
    # up" with every pod Running on the server, and nothing said whether the agents' node had never registered,
    # registered NotReady, or been refused its token.
    k get nodes -o wide 2>/dev/null || true
    echo "── the agents' node, as its k3s agent logged it"
    docker logs --tail 60 "$AGENTS_NODE" 2>&1 || true
    k get pods -A -o wide 2>/dev/null || true
    k logs -n vectispire-agents deploy/vs-vectispire-agent -c agent --tail 80 2>/dev/null || true
    k logs -n vectispire deploy/vs-vectispire --tail 40 2>/dev/null || true
    k get events -n vs-vectispire-scans --sort-by=.lastTimestamp 2>/dev/null | tail -20 || true
  fi
  if [ -z "${KEEP:-}" ]; then
    docker rm -f "$NAME" "$AGENTS_NODE" > /dev/null 2>&1 || true
    docker network rm "$NAME" > /dev/null 2>&1 || true
    # The matcher's database is written as uid 1000, the agent's, which the runner's user cannot delete on Linux:
    # removed by a container first, the rest by the runner.
    docker run --rm --network none -v "$work:/w" "$BASE_IMAGE" rm -rf /w/db > /dev/null 2>&1 || true
    rm -rf "$work"
  else
    echo "── kept: docker exec -it $NAME kubectl get pods -A ; work files in $work"
  fi
  exit "$status"
}
trap cleanup EXIT

# ── Images: the two Vectispire images built here unless named, and the fixture's.
if [ -z "$AGENT_IMAGE" ] && [ "$AGENT" = rust ]; then
  echo "── building the Rust agent's image"
  AGENT_IMAGE=vectispire-agent-rs:k8s-check
  docker build -q -f "$root/vectispire-rust/Dockerfile.agent" -t "$AGENT_IMAGE" "$root/vectispire-rust" > /dev/null
elif [ -z "$AGENT_IMAGE" ]; then
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

# ── The SSH fixture's keys: its host key, pinned in the chart's values, and the deployment key it accepts.
mkdir -p "$work/ssh"
ssh-keygen -q -t ed25519 -N '' -C k8s-check-host -f "$work/ssh/host_key"
ssh-keygen -q -t ed25519 -N '' -C k8s-check-deploy -f "$work/ssh/deploy"
cp "$work/ssh/deploy.pub" "$work/ssh/authorized_keys"
chmod 644 "$work/ssh/"*
SSH_HOST=ssh.scan-fixture.svc.cluster.local
# Another Service in front of the same sshd: the same key, under a name the pin does not list.
UNLISTED_HOST=ssh-unlisted.scan-fixture.svc.cluster.local
pinned_line="$SSH_HOST $(cut -d' ' -f1,2 "$work/ssh/host_key.pub")"

# ── The matcher's database, the composition check's fixture, imported by the pinned matcher itself into
# the layout `VulnerabilityDatabase` publishes: a generation, `current` naming it, `checked` just now.
mkdir -p "$work/matcher" "$work/db"
python3 "$fixture_dir/matcher-db.py" "$work/matcher/vulnerability.db" "$PACKAGE" 2.0
chmod 644 "$work/matcher/vulnerability.db"
chmod 777 "$work/db"
generation="$(python3 -c 'import time; print(int(time.time() * 1000))')-$(openssl rand -hex 4)"
# With retries, as the composition check pulls it: a registry timeout is not a cluster that cannot scan.
"$root/scripts/pull-pinned-image.sh" "$GRYPE_IMAGE"
docker run --rm --network none -u 1000:1000 -v "$work/db:/db" -v "$work/matcher:/in:ro" \
  -e "GRYPE_DB_CACHE_DIR=/db/vectispire-vulnerability-db/generations/$generation" \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false "$GRYPE_IMAGE" db import /in/vulnerability.db > /dev/null
# **And a gigabyte beside it, which the matcher never reads.** The one-advisory database is a few kilobytes, and
# the publisher's is some 3 GB: at the fixture's size the copy onto the cache volume passed while every real
# database was OOMKilled in the receiving container (64 MiB, the page cache of its writes charged to it) or
# timed out after the start timeout. The filler is what makes this run move a database's weight.
docker run --rm --network none -u 1000:1000 -v "$work/db:/db" --entrypoint sh "$BASE_IMAGE" -c '
  cd /db/vectispire-vulnerability-db && printf %s "$1" > current && date -u +%Y-%m-%dT%H:%M:%SZ > checked
  head -c 1073741824 /dev/zero > "generations/$1/filler"
  tar -C /db -cf /db/matcher.tar vectispire-vulnerability-db' sh "$generation"

# ── TLS for the Ingress, from an authority made for the run, and the agent's truststore holding it alone — in
# PKCS12 for the Java agent, and in PEM beside it (`ca.crt`, the same certificate) for the Rust agent, which reads no
# PKCS12 and refuses to start on the store alone.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=vectispire-k8s-check-ca \
  -keyout "$work/ca.key" -out "$work/ca.crt" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$HOST" -keyout "$work/tls.key" -out "$work/tls.csr" 2> /dev/null
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$HOST" > "$work/tls.ext"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 2 \
  -extfile "$work/tls.ext" -out "$work/tls.crt" 2> /dev/null
truststore_password="$(openssl rand -hex 12)"
# As the runner's user: run as the image's root, keytool left a file the runner could not chmod on Linux, where a
# container's files keep their owner (Docker Desktop hands them back, which is why the run passed on a laptop).
docker run --rm --network none -u "$(id -u):$(id -g)" -v "$work:/w" "$JDK_IMAGE" keytool -importcert -noprompt -alias check-ca \
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
# **The agent tunnel off** (`--egress-selector-mode=disabled`): the API server reaches the agents' node's kubelet
# directly. Through k3s's tunnel, an exec's stdin to a pod on that node was cut a few hundred kilobytes in once a
# transfer passed some 100 MB — containerd logged `stdin closed` — and the exec never reported its end: the
# matcher's database never reached its pod, and the step failed on its exec deadline (nightly 41664083661,
# 2026-11-03; 3.3 GB went through in 168 s without the tunnel). An operator's k3s needs the same flag.
docker run -d --privileged --name "$NAME" --hostname "$NAME" --network "$NAME" -p "127.0.0.1:$PORT:443" "$K3S_IMAGE" \
  server --disable=metrics-server --tls-san=127.0.0.1 --egress-selector-mode=disabled > /dev/null
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
# The fixture's base, beside the agent: what writes the matcher's database into the agent's work directory.
docker save vectispire-k8s-check-fixture-base:local | docker exec -i "$AGENTS_NODE" ctr -n k8s.io images import - > /dev/null
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
docker cp "$work/ssh/host_key" "$NAME:/tmp/ssh_host_key" && docker cp "$work/ssh/authorized_keys" "$NAME:/tmp/authorized_keys"
k create secret generic ssh-fixture -n scan-fixture --from-file=host_key=/tmp/ssh_host_key \
  --from-file=authorized_keys=/tmp/authorized_keys > /dev/null
docker exec "$NAME" rm -f /tmp/ssh_host_key /tmp/authorized_keys
# The same tree over SSH, as the composition check's `sshfixture` serves it: root, since sshd separates privileges
# and installs the keys it is handed at start.
k apply -f - > /dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: ssh, namespace: scan-fixture}
spec:
  selector: {matchLabels: {app: ssh}}
  template:
    metadata: {labels: {app: ssh}}
    spec:
      containers:
      - name: sshd
        image: docker.io/library/vectispire-k8s-check-fixture:local
        imagePullPolicy: Never
        securityContext: {runAsUser: 0}
        command: [sh, -c]
        args:
        - >-
          git config --system --add safe.directory '*' &&
          install -d -o git -m 700 /home/git/.ssh && install -o git -m 600 /keys/authorized_keys /home/git/.ssh/ &&
          install -m 600 /keys/host_key /etc/ssh/host_key &&
          exec /usr/sbin/sshd -D -e -o HostKey=/etc/ssh/host_key -o PasswordAuthentication=no
        ports: [{containerPort: 22}]
        volumeMounts: [{name: keys, mountPath: /keys, readOnly: true}]
        resources: {requests: {memory: 32Mi, cpu: 20m}}
      volumes: [{name: keys, secret: {secretName: ssh-fixture}}]
---
apiVersion: v1
kind: Service
metadata: {name: ssh, namespace: scan-fixture}
spec: {selector: {app: ssh}, ports: [{port: 22}]}
---
apiVersion: v1
kind: Service
metadata: {name: ssh-unlisted, namespace: scan-fixture}
spec: {selector: {app: ssh}, ports: [{port: 22}]}
EOF
k rollout status deployment/mysql -n vectispire --timeout=300s > /dev/null || fail "MySQL did not start"
k rollout status deployment/ssh -n scan-fixture --timeout=300s > /dev/null || fail "the SSH fixture did not start"

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
  trustStore: {secretName: vectispire-agent-trust, pemKey: ca.pem}
  knownHosts: "$pinned_line"
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
        ports: [{port: 9418}, {port: 22}]
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
docker cp "$work/truststore.p12" "$NAME:/tmp/truststore.p12" && docker cp "$work/ca.crt" "$NAME:/tmp/ca.pem"
k create secret generic vectispire-agent -n vectispire-agents \
  --from-file=token=/tmp/agent-token --from-file=signing-key=/tmp/agent-signing-key > /dev/null
k create secret generic vectispire-agent-trust -n vectispire-agents --from-file=truststore.p12=/tmp/truststore.p12 \
  --from-file=ca.pem=/tmp/ca.pem > /dev/null
docker exec "$NAME" rm -f /tmp/agent-token /tmp/agent-signing-key /tmp/tls.key

# The agent starts once its secrets exist; its start-up probe must pass under the chart's policies.
k rollout status deployment/vs-vectispire-agent -n vectispire-agents --timeout=600s > /dev/null \
  || fail "the agent did not start"
deadline=$(( $(date +%s) + 300 ))
until [[ "$(k logs -n vectispire-agents deploy/vs-vectispire-agent -c agent 2>/dev/null)" == *"the policies are enforced"* ]]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the agent never proved its scan pods are cut off"
  sleep 3
done
echo "✓ the agent started, and proved its scan pods cut off from the API server"

agent_pod="$(k get pods -n vectispire-agents -l app.kubernetes.io/component=agent -o jsonpath='{.items[0].metadata.name}')"
# **Into the agent's work directory from an ephemeral container of the fixture's base**, mounting the same volume as
# the agent's user: the Rust agent's image is `scratch`, with no `tar` to exec, and one way for both images is one
# check. Under the namespace's `restricted` level, as the agent itself runs — a numeric user, since the base's `git`
# cannot be verified as non-root.
printf '{"securityContext":{"runAsUser":1000,"runAsGroup":1000},"volumeMounts":[{"name":"work","mountPath":"%s"}]}' \
  "$AGENT_WORK" > "$work/loader.json"
chmod 644 "$work/loader.json"
docker cp "$work/loader.json" "$NAME:/tmp/loader.json"
k debug -n vectispire-agents "$agent_pod" --container=matcher-loader --profile=restricted --custom=/tmp/loader.json \
  --image=docker.io/library/vectispire-k8s-check-fixture-base:local --image-pull-policy=Never -- sleep 3600 > /dev/null
deadline=$(( $(date +%s) + 120 ))
until [ "$(k get pod -n vectispire-agents "$agent_pod" \
    -o jsonpath='{.status.ephemeralContainerStatuses[?(@.name=="matcher-loader")].state.running.startedAt}')" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the container loading the matcher's database did not start"
  sleep 2
done
docker cp "$work/db/matcher.tar" "$NAME:/tmp/matcher.tar"
docker exec "$NAME" sh -c "kubectl exec -i -n vectispire-agents $agent_pod -c matcher-loader -- tar -x -C $AGENT_WORK < /tmp/matcher.tar"

echo "── one repository, one scan"
repository="$({ bearer "$session"; body '{"url":"git://fixture.scan-fixture.svc.cluster.local/fixture.git","branch":"main","name":"k8s-check"}'; } \
  | curl_ -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/repositories")"
repo_id="$(printf '%s' "$repository" | json 'd["id"]' 2>/dev/null)" || fail "the fixture repository was refused: $repository"
# Runs one scan of repository $1 — or of image $1 with `container` as $2 — to its end and leaves its detail in $detail.
scan() {
  local response code answer status began=$SECONDS deadline=$(( $(date +%s) + 1800 ))
  local route=repositories filter=repo_id
  if [ "${2:-}" = container ]; then route=containers; filter=container_id; fi
  response="$(bearer "$session" | curl_ -K - -w '\n%{http_code}' -X POST "$base/api/v1/$route/$1/scan")"
  code="${response##*$'\n'}"; answer="${response%$'\n'*}"
  if [ "$code" = 200 ]; then
    scan_id="$(printf '%s' "$answer" | json 'd["id"]')"
  else
    # Queued by the schedule before this asked: the composition check's reading, the same scan either way.
    scan_id="$(bearer "$session" | curl_ -f -K - "$base/api/v1/scans?$filter=$1" \
      | json 'max((s["id"] for s in d if s["status"] in ("pending", "scanning")), default="")')"
    [ -n "$scan_id" ] || fail "the scan was refused ($code): $answer"
  fi
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
}
scan "$repo_id"

# Every scanner read the tree of the last scan ($detail) and found its plant.
read_the_tree() {
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
  || fail "the scan of $1 did not read the tree with every scanner"
}
read_the_tree git

# ── Over SSH, with a deployment key and the host's key pinned by the chart.
echo "── the same repository over SSH, its host key pinned in agents.knownHosts"
key_id="$({ bearer "$session"; body "$(python3 -c 'import json, sys; print(json.dumps({"name": "k8s-check",
    "private_key": open(sys.argv[1]).read(), "public_key": open(sys.argv[2]).read().strip()}))' \
    "$work/ssh/deploy" "$work/ssh/deploy.pub")"; } \
  | curl_ -f -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/ssh-keys" | json 'd["id"]')" \
  || fail "the deployment key was refused"
register_ssh() { # host, name -> repository id
  local registered
  registered="$({ bearer "$session"; body "{\"url\":\"ssh://git@$1/srv/fixture.git\",\"branch\":\"main\",\"name\":\"$2\",\"sshKeyId\":\"$key_id\"}"; } \
    | curl_ -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/repositories")"
  printf '%s' "$registered" | json 'd["id"]' 2>/dev/null || fail "the SSH repository on $1 was refused: $registered"
}
ssh_repo="$(register_ssh "$SSH_HOST" k8s-check-ssh)"
scan "$ssh_repo"
read_the_tree ssh
# Captured, then searched: `logs | grep -q` under pipefail reads a SIGPIPE as "not found".
agent_log="$(k logs -n vectispire-agents deploy/vs-vectispire-agent -c agent 2>/dev/null || true)"
case "$agent_log" in
  *"Creating directories for"*) fail "the agent has no writable home under the pin: JGit could not create its configuration" ;;
esac
echo "✓ an SSH clone matched the pinned host key, mounted where the agent reads it"

echo "── the same server by a name the pin does not list: refused, not learnt"
unlisted_repo="$(register_ssh "$UNLISTED_HOST" k8s-check-ssh-unlisted)"
scan "$unlisted_repo"
printf '%s' "$detail" | python3 -c '
import json, sys
s = json.load(sys.stdin)["scan"]; error = s["error"] or ""
if s["status"] != "failed" or "never added to" not in error:
    print("✗ a host the pin does not list was not refused as one: " + s["status"] + " — " + error, file=sys.stderr)
    sys.exit(1)' || fail "the pinned known_hosts was not read as the operator's pin"
echo "✓ a host the pin does not list is refused, and the pin is said to be read-only"

# ── An image target (decision 0045 §8): crane copies it in a pod of its own, online, for the platform the task asks
# (linux/amd64, whatever this machine is), and the cataloguer and the matcher read the archive offline. Alpine 3.20.3
# by its index digest, from Docker Hub: the online policy lets a scan pod out to the internet and nowhere else, so a registry on this
# machine's Docker network — inside `excludeCidrs` — would be refused, as it should. What it is judged by is its
# packages: the image's fourteen, by name, as syft reads them from `docker save`'s archive of the same image — so an
# archive crane wrote that the cataloguer read differently, or of another platform, fails here.
echo "── an image target, copied by crane in a pod and read offline"
# Manual only: a scheduled scan of a target never scanned is queued at once, and its pods were found still running
# by the check below that none outlived the scan (measured).
image="$({ bearer "$session"; body '{"registry":"docker.io","image_name":"library/alpine","tag":"sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a","scanManualOnly":true}'; } \
  | curl_ -K - -X POST -H 'Content-Type: application/json' "$base/api/v1/containers")"
image_id="$(printf '%s' "$image" | json 'd["id"]' 2>/dev/null)" || fail "the image target was refused: $image"
scan "$image_id" container
printf '%s' "$detail" | python3 -c '
import json, sys
d = json.load(sys.stdin); s = d["scan"]; problems = []
if s["status"] != "completed":
    problems.append("the image scan is " + s["status"] + ", not completed")
for step in (s["error"] or "").split(" | "):
    if step:
        problems.append("a step failed: " + step)
if not d["hasSbom"]:
    problems.append("no SBOM: the image was not copied, or the cataloguer did not read it")
if problems:
    print("\n".join("✗ " + p for p in problems), file=sys.stderr); sys.exit(1)' \
  || fail "the image target was not scanned through the Kubernetes executor"
bearer "$session" | curl_ -f -K - "$base/api/v1/scans/$scan_id/sbom" | python3 -c '
import json, sys
d = json.load(sys.stdin)
names = sorted({a["name"] for a in d["artifacts"] if a.get("type") == "apk"})
expected = sorted("alpine-baselayout alpine-baselayout-data alpine-keys apk-tools busybox busybox-binsh "
                  "ca-certificates-bundle libcrypto3 libssl3 musl musl-utils scanelf ssl_client zlib".split())
if names != expected:
    print("✗ the image SBOM holds " + ", ".join(names) + " where Alpine 3.20.3 holds " + ", ".join(expected),
          file=sys.stderr); sys.exit(1)
arches = {a.get("metadata", {}).get("architecture") for a in d["artifacts"] if a.get("type") == "apk"}
if "x86_64" not in arches or "aarch64" in arches:
    print("✗ the image SBOM holds packages of " + ", ".join(sorted(map(str, arches))) + ", not the amd64 asked for",
          file=sys.stderr); sys.exit(1)' \
  || fail "the image target's inventory is not Alpine 3.20.3's for linux/amd64"
echo "✓ an image target copied by crane in a pod: Alpine 3.20.3's fourteen packages, for linux/amd64"

# **The scan ran as pods, one per scanner**, scheduled in the scans' namespace — and the two probe pods
# before them — and none outlived it. Read from the cluster's events, since the agents list does not
# publish an agent's engine.
scheduled="$(k get events -n vs-vectispire-scans --field-selector reason=Scheduled \
  -o jsonpath='{range .items[*]}{.involvedObject.name}{"\n"}{end}')"
for pod in vs-network-probe vs-gitleaks-secret-detection vs-syft-directory-sbom vs-grype-sbom-analysis \
    vs-checkov-iac-analysis vs-semgrep-source-code-analysis vs-image-copy vs-syft-sbom-of-image-docker-io-library-alp \
    vs-grype-image-sbom-analysis; do
  grep -q "^$pod-[0-9a-f]\{10\}$" <<< "$scheduled" || fail "no $pod pod was scheduled in the scans' namespace"
done
# The matcher read its database from the cache volume, not a copy: k3s's local-path claim binds when a pod first
# mounts it, so a claim still pending is one no matcher pod used.
claim="$(k get pvc vs-vectispire-matcher-cache -n vs-vectispire-scans -o jsonpath='{.status.phase}' 2> /dev/null || true)"
[ "$claim" = Bound ] || fail "the matcher's cache claim is \"$claim\": the matcher did not read the database from it"
left="$(k get pods -n vs-vectispire-scans -l vectispire.dev/agent --no-headers 2>/dev/null | wc -l | tr -d ' ')"
[ "$left" = 0 ] || fail "$left scan pod(s) outlived the scan"

echo "✓ the chart's Kubernetes shape scans: every scanner ran as a pod, read the tree and found its plant, and an image" \
  "target was copied in a pod and read ($(elapsed "$started_at"))"
