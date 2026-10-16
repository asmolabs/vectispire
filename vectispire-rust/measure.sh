#!/bin/sh
# The Phase 0 measurements of README.md, reproducible: the image's size, the idle agent's memory on a
# long poll against a stub control plane, and grype's findings on the image. Throwaway containers,
# network and volume, all named vs-rs-measure-*, removed at the end.
set -eu
cd "$(dirname "$0")"
run=vs-rs-measure-$$
GRYPE=anchore/grype@sha256:"${GRYPE_DIGEST:?the digest ScannerImages pins for grype}"
cleanup() { docker rm -f "$run-stub" "$run-agent" >/dev/null 2>&1 || true; docker network rm "$run" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -q -f Dockerfile.agent -t vs-rs-agent:measure . >/dev/null
docker build -q -t vs-rs-forge:test crates/testkit/forge >/dev/null
echo "image, compressed:   $(docker save vs-rs-agent:measure | gzip -9 | wc -c | tr -d ' ') bytes"
echo "image, unpacked:     $(docker image inspect vs-rs-agent:measure --format '{{.Size}}') bytes (as the daemon reports it)"

docker network create "$run" >/dev/null
docker run -d --name "$run-stub" --network "$run" --entrypoint python3 \
  -v "$PWD/crates/testkit/stub/control_plane.py:/stub.py:ro" vs-rs-forge:test /stub.py >/dev/null
docker run -d --name "$run-agent" --network "$run" -e VECTISPIRE_URL="http://$run-stub:8080" \
  -e VECTISPIRE_AGENT_TOKEN=invented -e VECTISPIRE_AGENT_WAIT=30s vs-rs-agent:measure >/dev/null
sleep 45
echo "idle memory (cgroup): $(docker stats --no-stream --format '{{.MemUsage}}' "$run-agent")"
echo "threads:              $(docker stats --no-stream --format '{{.PIDs}}' "$run-agent")"
# The process's own resident set, read from its /proc by a container sharing its PID namespace.
docker run --rm --pid="container:$run-agent" busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
  sh -c 'grep -E "VmRSS|VmHWM" /proc/1/status' 
docker logs "$run-agent" 2>&1 | head -3

echo "packages the scanners see in the binary (cargo-auditable):"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro "$GRYPE" -q vs-rs-agent:measure -o json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(' ', len(d['source'] and d.get('matches',[])), 'matches'); print(' ', sorted({m['artifact']['name']+' '+m['artifact']['version']+' '+m['vulnerability']['id'] for m in d['matches']}))"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro "$GRYPE" -q vs-rs-agent:measure -o table || true
