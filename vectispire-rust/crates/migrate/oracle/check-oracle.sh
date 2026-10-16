#!/bin/sh
# The suite that holds vectispire-migrate to the real Flyway: a database Java migrated is validated
# and left alone by Rust, one Rust migrated is accepted by Java with the same schema, Java to V89 then
# Rust then Java again, and a Java and a Rust instance starting together. Both engines, develop's files
# and the 0.11.1 line's.
#
# Needs Docker, a JDK 25 (JAVA_HOME or `java` on PATH) and Gradle's cache for vectispire-core. A missing
# prerequisite fails the run; it never skips (AGENTS.md, "Never skip silently").
#
# `VECTISPIRE_REFERENCE_WRITE=1 oracle/check-oracle.sh` rewrites reference/migrate/ from Flyway's own
# output — on purpose, after a migration was added, never to make a failure go away.
set -eu
cd "$(dirname "$0")/../../.."
command -v docker >/dev/null || { echo "check-oracle.sh: Docker is required" >&2; exit 1; }
"${JAVA_HOME:+$JAVA_HOME/bin/}java" -version >/dev/null 2>&1 || { echo "check-oracle.sh: a JDK 25 is required" >&2; exit 1; }
exec cargo test -p vectispire-migrate --locked --features oracle --test oracle -- --test-threads=2 "$@"
