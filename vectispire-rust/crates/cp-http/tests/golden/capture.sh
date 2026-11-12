#!/bin/sh
# Re-records the Java control plane's HTTP answers (golden/java/) from a throwaway installation of the
# release this port follows: its own network, a MySQL as the composition pins it, both removed on exit.
# Run on purpose, never to make a test pass: a golden that changes is a change of the Java side's
# behaviour, and the Rust side follows it in the same commit (README.md, "The reference sets").
set -eu
cd "$(dirname "$0")"

IMAGE=${VECTISPIRE_GOLDEN_IMAGE:-ghcr.io/asmolabs/vectispire:0.11.0-rc.3@sha256:453aedcefc981ff9e91298c38db74138b027f5b1cac5e284fa889d1e264e1d46}
MYSQL=mysql:8.4.11@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70
NAME=vs-rs-http-$$
# Invented for this throwaway installation and nothing else.
DB_PASSWORD=vs-rs-http-db-pw
BOOTSTRAP='Vs-rs-http-bootstrap-Invented-1!'
KEY=dnMtcnMtaHR0cC1lbmNyeXB0aW9uLWtleS1pbnZlbnQ= # gitleaks:allow — base64 of an invented 32-byte label

cleanup() { docker rm -f "$NAME-app" "$NAME-db" >/dev/null 2>&1 || true; docker network rm "$NAME-net" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker network create "$NAME-net" >/dev/null
docker run -d --name "$NAME-db" --network "$NAME-net" --network-alias db -e MYSQL_ROOT_PASSWORD=$DB_PASSWORD \
  -e MYSQL_DATABASE=vectispire -e MYSQL_USER=vectispire -e MYSQL_PASSWORD=$DB_PASSWORD "$MYSQL" >/dev/null
i=0
until docker exec "$NAME-db" mysqladmin ping -h127.0.0.1 -uroot -p$DB_PASSWORD --silent >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 90 ] || { echo "MySQL did not start" >&2; exit 1; }; sleep 2
done
sleep 5
docker run -d --name "$NAME-app" --network "$NAME-net" -p 127.0.0.1::3180 \
  -e VECTISPIRE_DB_URL=jdbc:mysql://db:3306/vectispire -e VECTISPIRE_DB_USER=vectispire \
  -e VECTISPIRE_DB_PASSWORD=$DB_PASSWORD -e ENCRYPTION_KEY=$KEY -e VECTISPIRE_BOOTSTRAP_USERNAME=admin \
  -e "VECTISPIRE_BOOTSTRAP_PASSWORD=$BOOTSTRAP" -e VECTISPIRE_EMBEDDED_WORKER=false "$IMAGE" >/dev/null
PORT=$(docker port "$NAME-app" 3180/tcp | sed 's/.*://')
i=0
until curl -fs "http://127.0.0.1:$PORT/actuator/health" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 150 ] || { docker logs --tail 60 "$NAME-app" >&2; exit 1; }; sleep 2
done
python3 -I capture.py "http://127.0.0.1:$PORT" "$BOOTSTRAP" java
