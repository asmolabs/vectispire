#!/usr/bin/env bash
# The load test's environment: a MySQL of its own and the control plane's boot jar, nothing shared.
#
#   load/env.sh up      start MySQL (container + volume named below), then the control plane
#   load/env.sh app     (re)start the control plane only, against the running MySQL
#   load/env.sh stop    stop the control plane only (the data stays, for another run)
#   load/env.sh snapshot  copy the seeded database aside (stops both, restarts MySQL only)
#   load/env.sh restore   put the snapshot back, so a second campaign starts from the same rows
#   load/env.sh down    stop both and delete the container AND its volumes
#
# **Nothing here is the operator's.** `docker-compose.yml` gives its volumes fixed names, so a
# composition brought up "for a test" attaches to the real `vectispire_mysql_data`; this script does not
# use the composition at all, and refuses to start if the names it would create already exist and were
# not made by it (the label below). The test suites' `vectispire-test-mysql` is never touched either:
# a load run on it would slow every sibling's build and read their databases' noise as ours.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STATE="${LOAD_STATE_DIR:-$HERE/.state}"
mkdir -p "$STATE"

# The engine under test. 9.4 is the newest the campaign runs, 8.4 the oldest (decision 0043 §3);
# both digests are the ones the integration campaign pulled on 2026-10-30.
ENGINE="${LOAD_ENGINE:-mysql9}"
case "$ENGINE" in
  mysql9)  IMAGE="mysql:9.4@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2" ;;
  mysql84) IMAGE="mysql:8.4@sha256:c36050afdca850f23cef85703f84c7531a5ae155a11b5ee1c60acb09937c4084" ;;
  *) echo "LOAD_ENGINE must be mysql9 or mysql84" >&2; exit 2 ;;
esac
NAME="vectispire-loadtest-$ENGINE"
VOLUME="vectispire-loadtest-$ENGINE-data"
SNAPSHOT="vectispire-loadtest-$ENGINE-snapshot"
LABEL="com.asmolabs.vectispire.loadtest=$ENGINE"
DB_PORT="${LOAD_DB_PORT:-33906}"
APP_PORT="${LOAD_APP_PORT:-3190}"
# The Helm chart's default: a 2 GiB limit, of which the image's `MaxRAMPercentage=75` makes 1.5 GiB.
HEAP="${LOAD_HEAP:-1536m}"
# Hikari's default, which no shipped configuration changes. Raised only to measure the effect.
POOL="${LOAD_POOL_SIZE:-10}"
JAR="$ROOT/vectispire-java/vectispire-core/build/libs/vectispire-core.jar"

# Throwaway secrets, written once per state directory: none of them protects anything real.
secret() { [ -f "$STATE/$1" ] || openssl rand -hex "$2" > "$STATE/$1"; cat "$STATE/$1"; }
encryption_key() { [ -f "$STATE/encryption_key" ] || openssl rand -base64 32 > "$STATE/encryption_key"; cat "$STATE/encryption_key"; }

mysql_up() {
  if docker container inspect "$NAME" >/dev/null 2>&1; then
    [ "$(docker container inspect -f '{{index .Config.Labels "com.asmolabs.vectispire.loadtest"}}' "$NAME")" = "$ENGINE" ] \
      || { echo "$NAME exists and is not this harness's: refusing" >&2; exit 1; }
    docker start "$NAME" >/dev/null
  else
    if docker volume inspect "$VOLUME" >/dev/null 2>&1 \
        && [ "$(docker volume inspect -f '{{index .Labels "com.asmolabs.vectispire.loadtest"}}' "$VOLUME")" != "$ENGINE" ]; then
      echo "volume $VOLUME exists and is not this harness's: refusing" >&2; exit 1
    fi
    docker volume create --label "$LABEL" "$VOLUME" >/dev/null
    # The server's defaults, as the shipped composition runs it (its one option is the packet size),
    # plus what the measurement needs: the slow log at 200 ms, with the queries that use no index.
    docker run -d --name "$NAME" --label "$LABEL" \
      -p "127.0.0.1:$DB_PORT:3306" \
      -v "$VOLUME:/var/lib/mysql" \
      -e MYSQL_DATABASE=vectispire -e MYSQL_USER=vectispire \
      -e MYSQL_PASSWORD="$(secret db_password 18)" -e MYSQL_ROOT_PASSWORD="$(secret db_root_password 18)" \
      "$IMAGE" \
      --max-allowed-packet=160M \
      --slow-query-log=ON --long-query-time=0.2 --log-slow-extra=ON \
      --slow-query-log-file=/var/lib/mysql/slow.log >/dev/null
  fi
  echo -n "waiting for $NAME"
  for _ in $(seq 1 90); do
    if docker exec "$NAME" mysql -uvectispire -p"$(cat "$STATE/db_password")" -e 'select 1' vectispire >/dev/null 2>&1; then
      echo " ready"; return
    fi
    echo -n .; sleep 2
  done
  echo " timed out" >&2; exit 1
}

app_up() {
  [ -f "$JAR" ] || (cd "$ROOT/vectispire-java" && ./gradlew :vectispire-core:bootJar -x test -q)
  app_stop
  # Every limit a load generator meets on one address is lifted, and only those: the sign-in limit
  # (ten a minute per address) and the per-key request limit (600 a minute) would otherwise measure the
  # throttles. The built-in worker is off — the scans are executed by `seed/fake_agent.py`, through the
  # agent protocol, as a remote agent would.
  VECTISPIRE_DB_URL="jdbc:mysql://127.0.0.1:$DB_PORT/vectispire" \
  VECTISPIRE_DB_USER=vectispire VECTISPIRE_DB_PASSWORD="$(cat "$STATE/db_password")" \
  ENCRYPTION_KEY="$(encryption_key)" \
  VECTISPIRE_BOOTSTRAP_USERNAME=governor VECTISPIRE_BOOTSTRAP_PASSWORD="$(secret bootstrap_password 18)" \
  VECTISPIRE_EMBEDDED_WORKER=false VECTISPIRE_PORT="$APP_PORT" \
  VECTISPIRE_API_KEY_REQUESTS_PER_MINUTE=1000000 \
  nohup java -Xms"$HEAP" -Xmx"$HEAP" -XX:+UseG1GC \
    -Xlog:gc*:file="$STATE/gc.log":time,uptime:filecount=5,filesize=50m \
    -jar "$JAR" \
    --spring.datasource.hikari.maximum-pool-size="$POOL" \
    --vectispire.security.login-attempts-per-window=1000000 \
    --vectispire.jobs.maintenance-interval=24h \
    > "$STATE/app.log" 2>&1 &
  echo $! > "$STATE/app.pid"
  echo -n "waiting for the control plane on :$APP_PORT (pid $(cat "$STATE/app.pid"))"
  for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$APP_PORT/actuator/health" >/dev/null 2>&1; then echo " ready"; return; fi
    kill -0 "$(cat "$STATE/app.pid")" 2>/dev/null || { echo " died; see $STATE/app.log" >&2; exit 1; }
    echo -n .; sleep 2
  done
  echo " timed out" >&2; exit 1
}

app_stop() {
  # Only the PID this script started: other Java processes on the machine are other people's builds.
  if [ -f "$STATE/app.pid" ] && kill -0 "$(cat "$STATE/app.pid")" 2>/dev/null; then
    kill "$(cat "$STATE/app.pid")"
    for _ in $(seq 1 30); do kill -0 "$(cat "$STATE/app.pid")" 2>/dev/null || break; sleep 1; done
  fi
  rm -f "$STATE/app.pid"
}


# A copy of the data directory, made with the server stopped: a load run triages and rescans, so two
# campaigns compared (before and after a fix) must each start from the same rows.
copy_volume() {
  docker run --rm --label "$LABEL" -v "$1:/from:ro" -v "$2:/to" --entrypoint sh "$IMAGE" \
    -c 'rm -rf /to/* && cp -a /from/. /to/'
}

snapshot() {
  app_stop
  docker stop "$NAME" >/dev/null
  docker volume inspect "$SNAPSHOT" >/dev/null 2>&1 || docker volume create --label "$LABEL" "$SNAPSHOT" >/dev/null
  copy_volume "$VOLUME" "$SNAPSHOT"
  mysql_up
}

restore() {
  app_stop
  docker stop "$NAME" >/dev/null
  copy_volume "$SNAPSHOT" "$VOLUME"
  mysql_up
}

remove_volume() {
  if docker volume inspect "$1" >/dev/null 2>&1; then
    [ "$(docker volume inspect -f '{{index .Labels "com.asmolabs.vectispire.loadtest"}}' "$1")" = "$ENGINE" ] \
      && docker volume rm "$1" >/dev/null
  fi
}

down() {
  app_stop
  if docker container inspect "$NAME" >/dev/null 2>&1; then
    [ "$(docker container inspect -f '{{index .Config.Labels "com.asmolabs.vectispire.loadtest"}}' "$NAME")" = "$ENGINE" ] \
      && docker rm -f "$NAME" >/dev/null
  fi
  remove_volume "$VOLUME"
  remove_volume "$SNAPSHOT"
  rm -rf "$STATE"
}

case "${1:-}" in
  up) mysql_up; app_up ;;
  app) app_up ;;
  stop) app_stop ;;
  snapshot) snapshot ;;
  restore) restore ;;
  down) down ;;
  *) echo "usage: $0 up|app|stop|snapshot|restore|down" >&2; exit 2 ;;
esac
