#!/bin/sh
# The offline caches of the checked queries: one directory, `crates/cp-db/.sqlx/`, holding both engines.
#
#   crates/cp-db/scripts/sqlx-prepare.sh prepare   regenerate the caches from real databases and leave them in place
#   crates/cp-db/scripts/sqlx-prepare.sh check     regenerate into a scratch directory and fail if it differs from the
#                                     committed one, then compile offline with both engines on
#
# **Why a script and not `cargo sqlx prepare`.** The tool describes every query against *one*
# DATABASE_URL, and this crate has queries for two engines: pointed at MySQL, the PostgreSQL statements
# fail to describe. Each engine's queries are a feature (`mysql-queries`, `postgres-queries`); a pass
# compiles only that engine's against a database of that engine, with SQLX_OFFLINE_DIR set so that the
# macro writes what it learnt. The migrated schema comes from the real Flyway, as the tests' does.
#
# **What `check` is for.** An offline build reads the cache and nothing else: a changed query with an
# old cache fails to compile (no file for its hash), but a query *removed* leaves its file behind, and a
# regenerated cache for a changed schema differs from the committed one. `check` catches both, which is
# why a schema change and its cache travel in one commit.
#
# Containers and the network are named vs-rs-sqlx-*, removed on exit. A missing Docker fails the run.
set -eu
cd "$(dirname "$0")/../../.." # the workspace root, vectispire-rust/

mode="${1:-}"
case "$mode" in prepare | check) ;; *) echo "usage: $0 prepare|check" >&2; exit 2 ;; esac

committed="crates/cp-db/.sqlx"
migrations="$(cd ../vectispire-java/vectispire-core/src/main/resources/db/migration && pwd)"
# The campaign's engines and the Flyway Spring Boot's BOM brings, by digest (Engine.java, upgrade-drill.sh).
mysql_image="mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2"
postgres_image="postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
flyway_image="flyway/flyway:12.4.0@sha256:5be18367a9b3979a9f37234c371b80da457a448fb9577bd94d4bf24d923fafac"
password="throwaway-sqlx-prepare" # gitleaks:allow — invented, for containers removed on exit

suffix="$$"
network="vs-rs-sqlx-net-$suffix"
scratch="$(mktemp -d)"
cleanup() {
  docker rm -f "vs-rs-sqlx-mysql-$suffix" "vs-rs-sqlx-postgres-$suffix" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM
docker network create "$network" >/dev/null

# Waits for `$@` to succeed, for at most three minutes.
wait_for() {
  tries=0
  until "$@" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 360 ]; then
      echo "the database did not start" >&2
      exit 1
    fi
    sleep 0.5
  done
}

prepare_engine() { # engine feature
  engine="$1"
  feature="$2"
  out="$3"
  mkdir -p "$out"
  name="vs-rs-sqlx-$engine-$suffix"
  case "$engine" in
    mysql)
      docker run -d --name "$name" --network "$network" --network-alias db -p 127.0.0.1::3306 \
        -e MYSQL_ROOT_PASSWORD="$password" -e MYSQL_DATABASE=vectispire -e MYSQL_USER=vectispire \
        -e MYSQL_PASSWORD="$password" "$mysql_image" --default-time-zone=+00:00 >/dev/null
      wait_for docker exec "$name" mysql -uvectispire -p"$password" -h127.0.0.1 -e 'select 1' vectispire
      docker run --rm --network "$network" -v "$migrations:/migrations:ro" "$flyway_image" \
        -url="jdbc:mysql://db:3306/vectispire?allowPublicKeyRetrieval=true" -user=vectispire -password="$password" \
        -locations=filesystem:/migrations/common,filesystem:/migrations/mysql \
        -placeholders.ts='datetime(6)' -placeholders.id='bigint auto_increment primary key' \
        -placeholders.bool='bit(1)' -placeholders.true="b'1'" -placeholders.false="b'0'" \
        -placeholders.text=longtext -placeholders.double=double -placeholders.bytes=longblob migrate >/dev/null
      port="$(docker port "$name" 3306/tcp | head -n 1 | sed 's/.*://')"
      url="mysql://vectispire:$password@127.0.0.1:$port/vectispire"
      ;;
    postgres)
      docker run -d --name "$name" --network "$network" --network-alias db -p 127.0.0.1::5432 \
        -e POSTGRES_PASSWORD="$password" -e POSTGRES_USER=vectispire -e POSTGRES_DB=vectispire \
        "$postgres_image" >/dev/null
      wait_for docker exec "$name" psql -h 127.0.0.1 -U vectispire -tAc 'select 1'
      docker run --rm --network "$network" -v "$migrations:/migrations:ro" "$flyway_image" \
        -url="jdbc:postgresql://db:5432/vectispire" -user=vectispire -password="$password" \
        -locations=filesystem:/migrations/common,filesystem:/migrations/postgresql \
        -placeholders.ts='timestamp with time zone' -placeholders.id='bigint generated always as identity primary key' \
        -placeholders.bool=boolean -placeholders.true=true -placeholders.false=false \
        -placeholders.text=text -placeholders.double='double precision' -placeholders.bytes=bytea migrate >/dev/null
      port="$(docker port "$name" 5432/tcp | head -n 1 | sed 's/.*://')"
      url="postgres://vectispire:$password@127.0.0.1:$port/vectispire"
      ;;
  esac
  # The macros re-run only when their crate's source changes: touching the file forces a describe.
  touch crates/cp-db/src/store.rs
  DATABASE_URL="$url" SQLX_OFFLINE_DIR="$out" \
    cargo check -p vectispire-cp-db --lib --no-default-features --features "$feature" --locked
  docker rm -f "$name" >/dev/null
}

fresh="$scratch/sqlx"
mkdir -p "$fresh"
prepare_engine mysql mysql-queries "$fresh"
prepare_engine postgres postgres-queries "$fresh"

case "$mode" in
  prepare)
    rm -rf "$committed"
    mkdir -p "$committed"
    cp "$fresh"/query-*.json "$committed"/
    echo "wrote $(find "$committed" -name 'query-*.json' | wc -l | tr -d ' ') query files to $committed"
    ;;
  check)
    if ! diff -r "$fresh" "$committed"; then
      echo "the committed $committed is stale: run crates/cp-db/scripts/sqlx-prepare.sh prepare and commit the result" >&2
      exit 1
    fi
    # And the committed cache alone, no database, both engines on: what a build and CI compile with.
    touch crates/cp-db/src/store.rs
    SQLX_OFFLINE=true cargo check -p vectispire-cp-db --lib --locked
    echo "the offline caches are complete and current"
    ;;
esac
