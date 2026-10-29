#!/bin/sh
# Runs the real Flyway 12.4 with the Java control plane's configuration: FlywayOracle.java on
# vectispire-core's runtime classpath (Flyway, the JDBC drivers, and MigrationDialect itself).
#
#   oracle.sh migrate|check|validate|history <jdbc url> <user> <password> <vendor> [<db/migration root>|-] [<target>]
#   oracle.sh classpath     asks Gradle for the classpath if it is not kept yet, and stops there
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

# The suite runs two cases at a time, and on a fresh target directory both ask Gradle. A temporary file of each
# process's own: with one name for both, the first `mv` took the second's file away before its check, which then
# found nothing and failed the case ("Gradle printed no classpath"). The `mv` is atomic, so either result is whole.
if [ ! -s "$classpath_file" ]; then
    mkdir -p "$(dirname "$classpath_file")"
    pending="$classpath_file.$$.tmp"
    (cd "$repo/vectispire-java" && ./gradlew -q -I "$here/classpath.gradle" :vectispire-core:printRuntimeClasspath) \
        | sed -n 's/^CLASSPATH=//p' > "$pending"
    [ -s "$pending" ] || { rm -f "$pending"; echo "oracle.sh: Gradle printed no classpath" >&2; exit 1; }
    mv "$pending" "$classpath_file"
fi

[ "${1:-}" = "classpath" ] && exit 0
exec "$java" -cp "$(cat "$classpath_file")" "$here/FlywayOracle.java" "$@"
