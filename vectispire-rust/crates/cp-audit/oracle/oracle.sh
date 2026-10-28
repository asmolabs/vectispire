#!/bin/sh
# Runs the real Java audit log (AuditOracle.java) on vectispire-core's runtime classpath: the
# application's AuditLogService and AuditLogQueryService, its entities and repositories, Hibernate and the
# JDBC drivers it ships.
#
#   oracle.sh append|verify|export <jdbc url> <user> <password> [<count> <label> [<threads>]]
#
# The classpath is asked of Gradle once and kept in ORACLE_CLASSPATH_FILE (default: under the cargo
# target directory); delete the file after a dependency change. Needs a JDK 25 (`java` on PATH or
# JAVA_HOME). The JVM runs in UTC, as the control plane's images do.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
target=${CARGO_TARGET_DIR:-$repo/vectispire-rust/target}
classpath_file=${ORACLE_CLASSPATH_FILE:-$target/audit-oracle.classpath}
java=${JAVA_HOME:+$JAVA_HOME/bin/}java

if [ ! -s "$classpath_file" ]; then
    mkdir -p "$(dirname "$classpath_file")"
    # One scratch file per process: the suite runs two tests at once, and with no cache yet both ask Gradle — a shared
    # `.tmp` let one move the file away while the other still wrote it, which read as "no classpath".
    scratch="$classpath_file.tmp.$$"
    (cd "$repo/vectispire-java" && ./gradlew -q -I "$here/classpath.gradle" :vectispire-core:printAuditOracleClasspath) | sed -n 's/^CLASSPATH=//p' > "$scratch"
    [ -s "$scratch" ] || { rm -f "$scratch"; echo "oracle.sh: Gradle printed no classpath" >&2; exit 1; }
    mv "$scratch" "$classpath_file"
fi

exec "$java" -Duser.timezone="${ORACLE_TIMEZONE:-UTC}" -cp "$(cat "$classpath_file")" "$here/AuditOracle.java" "$@"
