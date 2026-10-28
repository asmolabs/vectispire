#!/bin/sh
# Installs the cargo subcommands the gate runs, at the versions tools.txt pins, into one directory shared
# by every checkout and worktree of this machine — so an agent working in a fresh worktree runs the whole
# gate instead of stopping at "no such command: deny", and a tool is built once, not once per worktree.
#
#   security/install-tools.sh [tool …]    installs those (all of tools.txt without arguments); quiet when current
#   security/install-tools.sh --bin       prints the directory to put on PATH
#
# The directory is $VECTISPIRE_RUST_TOOLS, by default ${XDG_CACHE_HOME:-~/.cache}/vectispire/rust-tools.
# `cargo install --locked` builds what the tool's own lockfile pins; a version already there is kept only
# when the binary itself reports the pinned one.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="${VECTISPIRE_RUST_TOOLS:-${XDG_CACHE_HOME:-$HOME/.cache}/vectispire/rust-tools}"
if [ "${1:-}" = "--bin" ]; then
  echo "$root/bin"
  exit 0
fi
pins="$(grep -v '^#' "$here/tools.txt" | grep -v '^$')"
# Split on purpose: one argument per tool name, and a name holds no space.
# shellcheck disable=SC2046
[ "$#" -gt 0 ] || set -- $(echo "$pins" | cut -d' ' -f1)
for tool in "$@"; do
  version="$(echo "$pins" | awk -v t="$tool" '$1 == t { print $2 }')"
  [ -n "$version" ] || { echo "install-tools.sh: $tool is not pinned in tools.txt" >&2; exit 2; }
  # Run as cargo runs it (`cargo-deny deny --version`) and on its own: the tools differ in which one answers,
  # and in the name they print before the version ("cargo-cyclonedx-cyclonedx 0.5.9"), so the version is
  # what is compared — the last word of a line naming the tool, or the word before the commit nextest adds
  # ("cargo-nextest 0.9.150 (d225b1daf 2026-10-26)").
  if [ -x "$root/bin/$tool" ] && { "$root/bin/$tool" "${tool#cargo-}" --version 2>/dev/null
                                   "$root/bin/$tool" --version 2>/dev/null; } \
      | grep -Eq "^${tool}[a-z-]* ${version}( \([^)]*\))?\$"; then
    continue
  fi
  echo "installing $tool $version into $root" >&2
  cargo install --locked --quiet --force --root "$root" "$tool@$version"
done
