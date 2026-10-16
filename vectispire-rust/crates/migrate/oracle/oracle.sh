#!/bin/sh
# Runs the real Flyway 12.4 with the Java control plane's configuration: FlywayOracle.java on
# vectispire-core's runtime classpath (Flyway, the JDBC drivers, and MigrationDialect itself).
#
#   oracle.sh migrate|check|validate|history <jdbc url> <user> <password> <vendor> [<db/migration root>|-] [<target>]
#
# The classpath is asked of Gradle once and kept in ORACLE_CLASSPATH_FILE (default: under the cargo
# target directory); delete the file after a dependency change. Needs a JDK 25 (`java` on PATH or
# JAVA_HOME) — the oracle is source launched, so nothing is compiled into the repository.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
target=${CARGO_TARGET_DIR:-$repo/vectispire-rust/target}
classpath_file=${ORACLE_CLASSPATH_FILE:-$target/flyway-oracle.classpath}
java=${JAVA_HOME:+$JAVA_HOME/bin/}java

if [ ! -s "$classpath_file" ]; then
    mkdir -p "$(dirname "$classpath_file")"
    (cd "$repo/vectispire-java" && ./gradlew -q -I "$here/classpath.gradle" :vectispire-core:printRuntimeClasspath) \
        | sed -n 's/^CLASSPATH=//p' > "$classpath_file.tmp"
    [ -s "$classpath_file.tmp" ] || { echo "oracle.sh: Gradle printed no classpath" >&2; exit 1; }
    mv "$classpath_file.tmp" "$classpath_file"
fi

exec "$java" -cp "$(cat "$classpath_file")" "$here/FlywayOracle.java" "$@"
