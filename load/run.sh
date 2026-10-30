#!/usr/bin/env bash
# Runs the scenario at each concurrency level and collects what each level did to the server.
#
#   LEVELS="1 10 50 100" DURATION=90s load/run.sh [label]
#
# Per level, under load/results/<date>-<label>/vus-<n>/: k6's summary (summary.json, and summary.txt —
# p50/p95/p99 per route), the pool/heap/GC samples (metrics.csv, metrics.json), and the statements
# MySQL spent its time on during that level (digests.txt, from performance_schema, reset before each
# level). The slow log (>200 ms) is copied once at the end.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${LOAD_STATE_DIR:-$HERE/.state}"
ENGINE="${LOAD_ENGINE:-mysql9}"
DB="vectispire-loadtest-$ENGINE"
APP_PORT="${LOAD_APP_PORT:-3190}"
LEVELS="${LEVELS:-1 10 50 100}"
DURATION="${DURATION:-90s}"
LABEL="${1:-run}"
OUT="$HERE/results/$(date +%Y-%m-%d-%H%M)-$LABEL"
# k6 1.3.0, by the multi-architecture index digest: the numbers are only comparable run to run if the
# load generator is the same one.
K6_IMAGE="grafana/k6:1.3.0@sha256:3ddc8b1a33a2c3d8edc6e99b6a762ae36cba08788463458f5e6a7703e14eb77d"
mkdir -p "$OUT"

[ -f "$STATE/seed.json" ] || { echo "no $STATE/seed.json: run load/seed/seed.py first" >&2; exit 1; }
[ -f "$STATE/bodies.json" ] || python3 "$HERE/seed/bodies.py" --seed-file "$STATE/seed.json" --out "$STATE/bodies.json"
PASSWORD="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$STATE/seed.json")"

sql() { docker exec -i "$DB" mysql -uroot -p"$(cat "$STATE/db_root_password")" vectispire -e "$1" 2>/dev/null; }

{
  echo "date: $(date -u +%FT%TZ)"
  echo "commit: $(git -C "$HERE" rev-parse --short HEAD)"
  echo "host: $(uname -sm), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo), $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus"
  echo "docker: $(docker info --format '{{.NCPU}} cpus, {{.MemTotal}} bytes, {{.OperatingSystem}}')"
  echo "java: $(java -version 2>&1 | head -1)"
  echo "jvm flags: $(ps -o args= -p "$(cat "$STATE/app.pid")" | tr ' ' '\n' | grep -E '^-X|pool-size' | tr '\n' ' ')"
  echo "mysql: $(sql 'select version()' | tail -1); buffer pool $(sql 'select @@innodb_buffer_pool_size' | tail -1) bytes; max_connections $(sql 'select @@max_connections' | tail -1)"
  echo "data: $(sql "select round(sum(data_length+index_length)/1048576) from information_schema.tables where table_schema='vectispire'" | tail -1) MB"
  sql "select 'issues', count(*) from t_issue union all select 'open issues', count(*) from t_issue where state='open'
       union all select 'findings', count(*) from t_finding union all select 'components', count(*) from t_component
       union all select 'scans', count(*) from t_scan union all select 'triage events', count(*) from t_issue_triage_event
       union all select 'repositories', count(*) from t_repository union all select 'containers', count(*) from t_container
       union all select 'accounts', count(*) from t_user" | tail -n +2
} > "$OUT/environment.txt"
cat "$OUT/environment.txt"

for vus in $LEVELS; do
  dir="$OUT/vus-$vus"
  mkdir -p "$dir"
  sql "truncate table performance_schema.events_statements_summary_by_digest"
  python3 "$HERE/sample.py" --base "http://127.0.0.1:$APP_PORT" --user ada.admin --password "$PASSWORD" \
    --csv "$dir/metrics.csv" --summary "$dir/metrics.json" &
  sampler=$!
  # The database's and the load generator's CPU, since both share the Docker VM's: a level whose MySQL
  # sits at the VM's ceiling is measuring the machine, and a pool raised there buys nothing.
  ( while true; do
      docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "$DB" $(docker ps -q --filter label=com.asmolabs.vectispire.loadtest=k6) 2>/dev/null \
        | sed "s/^/$(date +%H:%M:%S) /"
      sleep 3
    done ) > "$dir/docker-stats.txt" &
  stats=$!
  docker run --rm -i --label com.asmolabs.vectispire.loadtest=k6 \
    -v "$HERE:/load" \
    -e BASE="http://host.docker.internal:$APP_PORT" -e VUS="$vus" -e DURATION="$DURATION" \
    -e SEED_FILE=/load/.state/seed.json -e BODIES_FILE=/load/.state/bodies.json \
    -e SUMMARY_FILE="/load/results/$(basename "$OUT")/vus-$vus/summary.json" \
    ${GATE_RATE:+-e GATE_RATE="$GATE_RATE"} ${SCAN_RATE:+-e SCAN_RATE="$SCAN_RATE"} \
    ${LOGIN_RATE:+-e LOGIN_RATE="$LOGIN_RATE"} ${AGENTS:+-e AGENTS="$AGENTS"} ${THINK:+-e THINK="$THINK"} \
    "$K6_IMAGE" run --quiet /load/k6/scenario.js | tee "$dir/summary.txt"
  kill -TERM "$sampler"; wait "$sampler" || true
  kill "$stats" 2>/dev/null || true; wait "$stats" 2>/dev/null || true
  sql "select round(sum_timer_wait/1e12,2) as total_s, count_star as calls, round(avg_timer_wait/1e9,1) as avg_ms,
              round(max_timer_wait/1e9,1) as max_ms, round(sum_rows_examined/greatest(count_star,1)) as rows_exam_per_call,
              left(regexp_replace(digest_text, '[[:space:]]+', ' '), 260) as statement
       from performance_schema.events_statements_summary_by_digest
       where schema_name='vectispire' order by sum_timer_wait desc limit 25" > "$dir/digests.txt"
  echo "--- pool/heap/gc at $vus:"; cat "$dir/metrics.json"
done
docker exec "$DB" cat /var/lib/mysql/slow.log > "$OUT/slow.log" 2>/dev/null || true
echo "results in $OUT"
