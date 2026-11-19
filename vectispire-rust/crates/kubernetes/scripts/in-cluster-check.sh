#!/bin/sh
# The Rust agent's start inside a cluster, as the chart runs it (decision 0045): its image in a pod of its own
# namespace, under a service account bound to the chart's Role in the scans' namespace, the chart's two policies on
# that namespace — and a control plane that does not answer, since what is checked here is everything the agent does
# before its hello:
#
#   - the API server's address from the kubelet's variables, checked against kubernetes.default.svc by the image's
#     own resolver (a static musl binary on `scratch`) before the token goes there;
#   - the projected token and the cluster's CA, read where Kubernetes mounts them;
#   - its own uid:gid read off its work directory, this agent's leftovers swept, Pod Security proved by a dry run,
#     and scan pods proved cut off from the API server, offline and online.
#
# The start passes all of them when the log says the control plane is unreachable and is being retried. Needs Docker;
# builds the image from Dockerfile.agent (minutes: a release build with LTO), starts k3s, removes both after.
#
#   crates/kubernetes/scripts/in-cluster-check.sh
set -eu
cd "$(dirname "$0")/../../.."
K3S="rancher/k3s:v1.34.12-k3s1@sha256:4ea0adb6b0ffedab0c58ffe5c99a49f2f7be871f38636c8baa2692899648d8c5"
IMAGE="vs-rs-agent:in-cluster-check"
NAME="vs-rs-k3s-in-cluster-$$"
SCANS=vectispire-scans
AGENTS=vectispire

docker build -q -f Dockerfile.agent -t "$IMAGE" . >/dev/null
docker run -d --name "$NAME" --label dev.vectispire.test=rust --privileged "$K3S" server \
  --disable=traefik,metrics-server,servicelb >/dev/null
trap 'docker rm -f -v "$NAME" >/dev/null 2>&1 || true' EXIT
k() { docker exec "$NAME" kubectl "$@"; }
apply() { docker exec -i "$NAME" kubectl apply -f - >/dev/null; }
wait_for() {
  i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 180 ] || { echo "in-cluster-check: never: $*"; exit 1; }; sleep 1
  done
}
wait_for k get --raw /readyz
wait_for k wait --for=condition=Ready node --all --timeout=5s
wait_for k get serviceaccount default -n default
# The cluster's DNS answering: the agent checks the API server's address against it, and refuses to start without it.
wait_for k rollout status deployment/coredns -n kube-system --timeout=5s

# The image, as the cluster's runtime sees it: never pulled.
docker save "$IMAGE" | docker exec -i "$NAME" ctr -n k8s.io images import - >/dev/null

k create namespace "$SCANS" >/dev/null
k label namespace "$SCANS" pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest >/dev/null
k create namespace "$AGENTS" >/dev/null
k create serviceaccount vectispire-agent -n "$AGENTS" >/dev/null
rules=$(sed -n '/^kind: Role$/,/^---$/p' ../deploy/helm/vectispire/templates/agents/scans-role.yaml | sed -n '/^rules:$/,/^---$/p' | sed '$d')
case "$rules" in *pods/exec*) ;; *) echo "in-cluster-check: the chart's Role rules were not found"; exit 1 ;; esac
service=$(k get service kubernetes -n default -o 'jsonpath={.spec.clusterIP}')
endpoint=$(k get endpoints kubernetes -n default -o 'jsonpath={.subsets[0].addresses[0].ip}')
apply <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: vectispire-agent, namespace: $SCANS}
$rules
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: vectispire-agent, namespace: $SCANS}
subjects: [{kind: ServiceAccount, name: vectispire-agent, namespace: $AGENTS}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: vectispire-agent}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: scans-offline, namespace: $SCANS}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: scans-online, namespace: $SCANS}
spec:
  podSelector: {matchLabels: {vectispire.dev/network: egress}}
  policyTypes: [Egress]
  egress:
  - ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]
  - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [169.254.0.0/16, $service/32, $endpoint/32]}}]
---
apiVersion: v1
kind: Pod
metadata: {name: agent, namespace: $AGENTS}
spec:
  serviceAccountName: vectispire-agent
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, seccompProfile: {type: RuntimeDefault}}
  volumes: [{name: work, emptyDir: {}}]
  containers:
  - name: agent
    image: $IMAGE
    imagePullPolicy: Never
    env:
    - {name: VECTISPIRE_URL, value: "https://127.0.0.1:9"}
    - {name: VECTISPIRE_AGENT_TOKEN, value: "vsk_in_cluster_check"}
    - {name: VECTISPIRE_AGENT_RETRY, value: "5s"}
    - {name: VECTISPIRE_WORK_DIR, value: /work}
    - {name: VECTISPIRE_AGENT_EXECUTOR, value: kubernetes}
    - {name: VECTISPIRE_SCANS_NAMESPACE, value: $SCANS}
    - {name: VECTISPIRE_AGENT_NAME, value: release-agent}
    - {name: VECTISPIRE_KUBERNETES_SCAN_CPU_MILLIS, value: "250"}
    - {name: VECTISPIRE_KUBERNETES_SCAN_MEMORY_MIB, value: "128"}
    volumeMounts: [{name: work, mountPath: /work}]
    securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF

i=0
until k logs agent -n "$AGENTS" 2>/dev/null | grep -q "The control plane is unreachable"; do
  i=$((i + 1))
  if [ "$i" -ge 300 ] || k get pod agent -n "$AGENTS" -o 'jsonpath={.status.phase}' | grep -q Failed; then
    echo "in-cluster-check: the agent did not reach its hello. Its log:"; k logs agent -n "$AGENTS" || true; exit 1
  fi
  sleep 1
done
log=$(k logs agent -n "$AGENTS")
echo "$log"
for said in "refuses a privileged pod: Pod Security restricted is enforced" \
            "Scan pods are cut off from the API server at $service:443, offline and online"; do
  echo "$log" | grep -q "$said" || { echo "in-cluster-check: the log does not say: $said"; exit 1; }
done
echo "in-cluster-check: the Rust agent starts in the cluster with the Kubernetes executor."
