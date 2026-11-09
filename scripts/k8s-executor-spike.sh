#!/bin/sh
# The Kubernetes scan executor's mechanism, run against a real cluster (decision 0045): what the Java
# backend will do, step by step, with kubectl — and the three measurements 0045 requires before the
# backend scans for an installation. Run it on the target cluster as well as on a throwaway one.
#
#   KUBECONFIG=… scripts/k8s-executor-spike.sh            (namespace vectispire-scans-spike, removed at the end)
#
# It needs kubectl and the right to create a namespace; everything it creates is in that namespace and
# deleted on exit. It pulls three pinned images (busybox, gitleaks) onto a node.
#
# Checks, each printed PASS or FAIL, and the run fails on any FAIL — nothing is skipped:
#   1. the namespace enforces Pod Security `restricted`: a root pod is refused by the API server;
#   2. a pod labelled offline cannot reach the outside (the NetworkPolicy is enforced by the CNI);
#   3. a memory-backed emptyDir with sizeLimit answers ENOSPC, rather than an eviction;
#   4. one scan step end to end: a workspace copied in over exec + tar, gitleaks run on it with no network
#      under `restricted`, its report read back over exec from a holder, the planted finding in it.
set -eu

NS="${NS:-vectispire-scans-spike}"
BUSYBOX="busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
GITLEAKS="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
WORK="$(mktemp -d)"
failed=0

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }
cleanup() { kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# The securityContext every scan container gets: the closed shape's properties Kubernetes expresses.
restricted='{"runAsNonRoot": true, "runAsUser": 1000, "runAsGroup": 1000, "allowPrivilegeEscalation": false,
  "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}'

wait_for() { # <seconds> <command…>: polls once a second until the command succeeds
  seconds="$1"; shift
  i=0; until "$@" >/dev/null 2>&1; do i=$((i + 1)); [ "$i" -ge "$seconds" ] && return 1; sleep 1; done
}

kubectl create namespace "$NS" >/dev/null
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest >/dev/null

# Offline steps: no ingress, no egress at all — not even DNS.
kubectl apply -n "$NS" -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: offline}
spec:
  podSelector: {matchLabels: {vectispire.dev/network: none}}
  policyTypes: [Ingress, Egress]
EOF

# ── 1. restricted is enforced ──
if kubectl run root-probe -n "$NS" --image="$BUSYBOX" --restart=Never \
     --overrides='{"spec":{"containers":[{"name":"root-probe","image":"'"$BUSYBOX"'","command":["true"],"securityContext":{"runAsUser":0}}]}}' \
     >/dev/null 2>"$WORK/psa.err"; then
  fail "1. a root pod was admitted: the namespace does not enforce Pod Security restricted"
else
  if grep -q 'restricted' "$WORK/psa.err"; then pass "1. Pod Security restricted refuses a root pod"
  else fail "1. the root pod was refused, but not by Pod Security: $(head -c 300 "$WORK/psa.err")"; fi
fi

# ── 2. the offline policy is enforced ──
kubectl apply -n "$NS" -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: network-probe, labels: {vectispire.dev/network: none}}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
  - name: probe
    image: $BUSYBOX
    command: [sh, -c, "sleep 3; if wget -q -T 5 -O /dev/null http://1.1.1.1/ 2>/dev/null; then echo REACHED; else echo BLOCKED; fi"]
    securityContext: $restricted
EOF
if wait_for 120 sh -c "kubectl get pod network-probe -n $NS -o jsonpath='{.status.phase}' | grep -Eq 'Succeeded|Failed'"; then
  case "$(kubectl logs network-probe -n "$NS")" in
    *BLOCKED*) pass "2. an offline pod cannot reach the outside" ;;
    *REACHED*) fail "2. an offline pod reached 1.1.1.1: this CNI does not enforce NetworkPolicy" ;;
    *) fail "2. the network probe said nothing readable" ;;
  esac
else fail "2. the network probe never finished"; fi

# ── 3. a memory-backed emptyDir with sizeLimit answers ENOSPC ──
kubectl apply -n "$NS" -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: size-probe, labels: {vectispire.dev/network: none}}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  volumes: [{name: out, emptyDir: {medium: Memory, sizeLimit: 8Mi}}]
  containers:
  - name: probe
    image: $BUSYBOX
    command: [sh, -c, "dd if=/dev/zero of=/out/fill bs=1M count=32 2>&1; echo dd-exit=\$?; echo size=\$(wc -c < /out/fill)"]
    volumeMounts: [{name: out, mountPath: /out}]
    resources: {limits: {memory: 256Mi, cpu: 500m}, requests: {memory: 256Mi, cpu: 500m}}
    securityContext: $restricted
EOF
if wait_for 120 sh -c "kubectl get pod size-probe -n $NS -o jsonpath='{.status.phase}' | grep -Eq 'Succeeded|Failed'"; then
  reason="$(kubectl get pod size-probe -n "$NS" -o jsonpath='{.status.reason}')"
  out="$(kubectl logs size-probe -n "$NS" 2>/dev/null || true)"
  if [ "$reason" = "Evicted" ]; then fail "3. the write past sizeLimit was evicted, not refused (0038's objection holds here)"
  elif echo "$out" | grep -qi 'no space left'; then pass "3. a write past a memory-backed sizeLimit gets ENOSPC"
  else fail "3. neither ENOSPC nor an eviction: $(echo "$out" | head -c 200)"; fi
else fail "3. the size probe never finished"; fi

# ── 4. one scan step end to end ──
mkdir -p "$WORK/ws/source"
# A token of the shape gitleaks' aws-access-token rule matches, generated here so no file of this
# repository carries one.
token="AKIA$(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c 16)"
printf 'aws_access_key_id = %s\n' "$token" > "$WORK/ws/source/settings.ini"
tar -C "$WORK/ws" -cf "$WORK/ws.tar" .

# The workspace is received by an init container that waits for it, so the scanner cannot start on a
# half-copied tree; the holder is a regular container that outlives the scanner so its report can be
# read: a native sidecar would be stopped with the pod as soon as the scanner exits.
kubectl apply -n "$NS" -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: scan-step, labels: {vectispire.dev/network: none, vectispire.dev/scanner: gitleaks}}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  activeDeadlineSeconds: 600
  volumes:
  - {name: repo, emptyDir: {}}
  - {name: tmp, emptyDir: {medium: Memory, sizeLimit: 64Mi}}
  initContainers:
  - name: receive
    image: $BUSYBOX
    command: [sh, -c, "until [ -f /repo/.received ]; do sleep 1; done"]
    volumeMounts: [{name: repo, mountPath: /repo}]
    securityContext: $restricted
  containers:
  - name: scanner
    image: $GITLEAKS
    args: [detect, --source=/repo/source, --no-git, --report-format=json, --report-path=/repo/report.json, --exit-code=0]
    env: [{name: HOME, value: /tmp}]
    volumeMounts: [{name: repo, mountPath: /repo}, {name: tmp, mountPath: /tmp}]
    resources: {limits: {memory: 512Mi, cpu: "1"}, requests: {memory: 512Mi, cpu: "1"}}
    securityContext: $restricted
  - name: holder
    image: $BUSYBOX
    command: [sh, -c, "sleep 900"]
    volumeMounts: [{name: repo, mountPath: /repo, readOnly: true}]
    resources: {limits: {memory: 32Mi, cpu: 100m}, requests: {memory: 32Mi, cpu: 100m}}
    securityContext: $restricted
EOF

receiving() { [ "$(kubectl get pod scan-step -n "$NS" -o jsonpath='{.status.initContainerStatuses[0].state.running.startedAt}')" != "" ]; }
scanner_done() { [ "$(kubectl get pod scan-step -n "$NS" -o jsonpath='{.status.containerStatuses[?(@.name=="scanner")].state.terminated.exitCode}')" != "" ]; }

if ! wait_for 180 receiving; then fail "4. the receiving init container never ran"; else
  kubectl exec -i -n "$NS" scan-step -c receive -- tar -x -C /repo < "$WORK/ws.tar"
  kubectl exec -n "$NS" scan-step -c receive -- touch /repo/.received
  if ! wait_for 300 scanner_done; then fail "4. the scanner never finished"; else
    code="$(kubectl get pod scan-step -n "$NS" -o jsonpath='{.status.containerStatuses[?(@.name=="scanner")].state.terminated.exitCode}')"
    owner="$(kubectl exec -n "$NS" scan-step -c holder -- stat -c '%u' /repo/source/settings.ini)"
    # Capped, as the agent's read will be: past the ceiling is a failure, never a truncation.
    kubectl exec -n "$NS" scan-step -c holder -- head -c 1048577 /repo/report.json > "$WORK/report.json"
    size="$(wc -c < "$WORK/report.json" | tr -d ' ')"
    if [ "$code" != 0 ]; then fail "4. gitleaks exited $code"
    elif [ "$size" -gt 1048576 ]; then fail "4. the report is past its ceiling"
    elif grep -q "$token" "$WORK/report.json" && grep -q '"RuleID"' "$WORK/report.json"; then
      pass "4. workspace in over exec, gitleaks offline under restricted, report out over exec: the planted token found (files owned by uid $owner)"
    else fail "4. the report does not name the planted token: $(head -c 300 "$WORK/report.json")"; fi
  fi
fi

if [ "$failed" = 0 ]; then echo "All checks passed."; else echo "Some checks failed."; exit 1; fi
