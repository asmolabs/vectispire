#!/bin/sh
# The suite that holds cp-audit to the real Java audit log, on both engines: a chain Java started continues
# in Rust and Java verifies it, one Rust extended continues in Java and Rust verifies it, a Java and a Rust
# writer at once keep one chain, and the evidence bundle's lines are Java's bytes.
#
# Needs Docker, a JDK 25 (JAVA_HOME or `java` on PATH) and Gradle's cache for vectispire-core. A missing
# prerequisite fails the run; it never skips (AGENTS.md, "Never skip silently").
set -eu
cd "$(dirname "$0")/../../.."
command -v docker >/dev/null || { echo "check-oracle.sh: Docker is required" >&2; exit 1; }
"${JAVA_HOME:+$JAVA_HOME/bin/}java" -version >/dev/null 2>&1 || { echo "check-oracle.sh: a JDK 25 is required" >&2; exit 1; }
exec cargo test -p vectispire-cp-audit --locked --features oracle --test oracle -- --test-threads=2 "$@"
