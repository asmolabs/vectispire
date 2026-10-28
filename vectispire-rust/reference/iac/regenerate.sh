#!/bin/sh
# Regenerates the real runs of the IaC reference set (runs/01- to 04-): the pinned checkov image on
# small trees, as the agent runs it. The edges (05- on) are written by hand and kept as they are.
#
# **Not deterministic**: the tools print timings and, for checkov, its checks in no fixed order. A
# regeneration therefore changes these files, and the Java answers must be rewritten after it.
#
# Then regenerate the Java answers and make the Rust port agree (README.md, "The reference sets"):
#   ./gradlew :vectispire-common:test --tests '*IacReferenceSetTest*' -Dvectispire.rust.reference.write=true
#
# The trees are written here rather than committed: a deliberately insecure Dockerfile in the
# repository would fail this repository's own checkov policy.
set -eu
cd "$(dirname "$0")"
image=$(sed -n 's/.*"\(bridgecrew\/checkov@sha256:[0-9a-f]*\)".*/\1/p' ../../crates/scanners/src/images.rs)
[ -n "$image" ] || { echo "no checkov pin in images.rs" >&2; exit 1; }
root=$(mktemp -d "${TMPDIR:-/tmp}/vs-rs-iac.XXXXXX")
trap 'rm -rf "$root"' EXIT
mk() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

mk "$root/terraform/source/main.tf" <<'TF'
resource "aws_s3_bucket" "reports" {
  bucket = "example-reports"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
TF

mk "$root/mixed/source/infra/main.tf" <<'TF'
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
}
TF
mk "$root/mixed/source/k8s/deployment.yaml" <<'K8S'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:latest
          securityContext:
            privileged: true
K8S
mk "$root/mixed/source/Dockerfile" <<'DF'
FROM alpine:3.20
RUN apk add curl
ADD https://example.org/tool.tar.gz /opt/
DF

mk "$root/no-iac/source/README.md" <<'MD'
Nothing for an infrastructure checker here.
MD

mk "$root/sub-path/source/app/README.md" <<'MD'
Application code, out of the scanned subdirectory.
MD
mk "$root/sub-path/source/deploy/main.tf" <<'TF'
resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 10
}
TF

# The scan as the agent runs it: no network, read-only root, no capability, the workspace read-only,
# as the workspace's owner. What the container prints is kept as the run's stdout and stderr.
scan() {
  ws=$1; image=$2; out=$3; shift 3
  set +e
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 512 --memory 2g --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,noexec,nosuid,mode=1777,size=512m \
    --tmpfs /home/scanner:rw,noexec,nosuid,mode=1777,size=512m \
    -e HOME=/home/scanner -e TMPDIR=/tmp -e XDG_CACHE_HOME=/home/scanner/.cache \
    -v "$ws:/repo:ro" "$image" "$@" >"$out.stdout" 2>/dev/null
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then printf 'exit=%s\n' "$code" >>"$out.case"; fi
}

for pair in terraform:01-terraform mixed:02-mixed-frameworks no-iac:03-no-infrastructure; do
  tree=${pair%%:*}; name=${pair#*:}
  rm -f "runs/$name.case"
  scan "$root/$tree" "$image" "runs/$name" -d /repo/source -o json --soft-fail --compact
done
printf 'subPath=deploy\n' >runs/04-sub-path.case
scan "$root/sub-path" "$image" runs/04-sub-path -d /repo/source/deploy -o json --soft-fail --compact
